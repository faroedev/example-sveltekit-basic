import { fail, redirect } from "@sveltejs/kit";
import { FaroeError, verifyEmailInput, verifyPasswordInput } from "@faroe/sdk";
import { getUserFromEmail } from "$lib/server/user";
import { faroe } from "$lib/server/faroe";
import { createSession, generateSessionToken, setSessionTokenCookie } from "$lib/server/session";

import type { Actions, RequestEvent } from "./$types";

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
		let email = formData.get("email");
		const password = formData.get("password");
		if (typeof email !== "string" || typeof password !== "string") {
			return fail(400, {
				message: "Invalid or missing fields."
			});
		}
		email = email.toLowerCase();

		if (email === "" || password === "") {
			return fail(400, {
				message: "Please enter your email and password."
			});
		}
		if (!verifyEmailInput(email)) {
			return fail(400, {
				email,
				message: "Please enter a valid email address."
			});
		}
		if (!verifyPasswordInput(password)) {
			return {
				email,
				message: "Please enter a valid password."
			};
		}

		const user = getUserFromEmail(email);
		if (user === null) {
			return {
				email,
				message: "Account does not exist."
			};
		}

		try {
			await faroe.verifyUserPassword(user.faroeId, password, "0.0.0.0");
		} catch (e) {
			if (e instanceof FaroeError && e.code === "INCORRECT_PASSWORD") {
				return fail(400, {
					email,
					message: "Incorrect password."
				});
			}
			if (e instanceof FaroeError && e.code === "TOO_MANY_REQUESTS") {
				return fail(420, {
					email,
					message: "Please try again later."
				});
			}
			return fail(500, {
				email,
				message: "An unknown error occurred. Please try again later."
			});
		}

		const sessionToken = generateSessionToken();
		const session = createSession(sessionToken, user.id, null);

		setSessionTokenCookie(event, sessionToken, session.expiresAt);
		return redirect(302, "/");
	}
};
