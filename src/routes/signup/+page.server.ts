import { fail, redirect } from "@sveltejs/kit";
import { FaroeError, verifyEmailInput, verifyPasswordInput } from "@faroe/sdk";
import { createUser, getUserFromEmail } from "$lib/server/user";
import { faroe } from "$lib/server/faroe";
import { createSession, generateSessionToken, setSessionTokenCookie } from "$lib/server/session";

import type { Actions, RequestEvent } from "./$types";
import type { FaroeUser } from "@faroe/sdk";
import type { User } from "$lib/server/user";

export async function load(event: RequestEvent) {
	if (event.locals.user !== null) {
		if (!event.locals.user.emailVerified) {
			return redirect(302, "/verify-email");
		}
		return redirect(302, "/");
	}
	return {};
}

export const actions: Actions = {
	async default(event) {
		const formData = await event.request.formData();
		const username = formData.get("username");
		const email = formData.get("email");
		const password = formData.get("password");
		if (typeof username !== "string" || typeof email !== "string" || typeof password !== "string") {
			return fail(400, {
				username: "",
				email: "",
				message: "Invalid or missing fields."
			});
		}
		if (username === "" || email === "" || password === "") {
			return fail(400, {
				username,
				email,
				message: "Please enter your username, email, and password."
			});
		}

		if (username.length < 3 || username.length >= 32 || !/[A-Za-z0-9]/.test(username)) {
			return fail(400, {
				username,
				email,
				message: "Please enter a valid username."
			});
		}
		if (!verifyEmailInput(email)) {
			return fail(400, {
				username,
				email,
				message: "Please enter a valid email address."
			});
		}

		const existingUser = getUserFromEmail(email);
		if (existingUser !== null) {
			return fail(400, {
				username,
				email,
				message: "Email is already used."
			});
		}

		if (!verifyPasswordInput(password)) {
			return fail(400, {
				username,
				email,
				message: "Please enter a valid password."
			});
		}

		let faroeUser: FaroeUser;
		try {
			faroeUser = await faroe.createUser(password, "0.0.0.0");
		} catch (e) {
			if (e instanceof FaroeError && e.code === "WEAK_PASSWORD") {
				return fail(400, {
					username,
					email,
					message: "Please use a stronger password."
				});
			}
			if (e instanceof FaroeError && e.code === "TOO_MANY_REQUESTS") {
				return fail(429, {
					username,
					email,
					message: "Please try again later."
				});
			}
			return fail(500, {
				username,
				email,
				message: "An unknown error occurred. Please try again later."
			});
		}

		let user: User;
		try {
			user = createUser(faroeUser.id, email, username);
		} catch {
			await faroe.deleteUser(faroeUser.id);
			return fail(500, {
				username,
				email,
				message: "An unknown error occurred. Please try again later."
			});
		}

		const verificationRequest = await faroe.createUserEmailVerificationRequest(user.faroeId);
		console.log(`To ${user.email}: Your code is ${verificationRequest.code}`);

		const sessionToken = generateSessionToken();
		const session = createSession(sessionToken, user.id, null);

		setSessionTokenCookie(event, sessionToken, session.expiresAt);
		return redirect(302, "/verify-email");
	}
};
