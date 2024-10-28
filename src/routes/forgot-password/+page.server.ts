import { fail, redirect } from "@sveltejs/kit";
import { FaroeError, verifyEmailInput } from "@faroe/sdk";
import { getUserFromEmail } from "$lib/server/user";
import { faroe } from "$lib/server/faroe";
import { generateSessionToken } from "$lib/server/session";
import { createPasswordResetSession, setPasswordResetSessionTokenCookie } from "$lib/server/password-reset-session";

import type { Actions } from "./$types";
import type { FaroePasswordResetRequest } from "@faroe/sdk";

export const actions: Actions = {
	async default(event) {
		const formData = await event.request.formData();
		const email = formData.get("email");
		if (typeof email !== "string") {
			return fail(400, {
				email: "",
				message: "Invalid or missing fields."
			});
		}
		if (email === "") {
			return fail(400, {
				email: "",
				message: "Please enter your email address."
			});
		}
		if (!verifyEmailInput(email)) {
			return fail(400, {
				email,
				message: "Please enter a valid email address."
			});
		}

		const user = getUserFromEmail(email);
		if (user === null) {
			return fail(400, {
				email,
				message: "Account does not exist."
			});
		}

		let resetRequest: FaroePasswordResetRequest;
		let verificationCode: string;
		try {
			[resetRequest, verificationCode] = await faroe.createUserPasswordResetRequest(user.faroeId, "0.0.0.0");
		} catch (e) {
			if (e instanceof FaroeError && e.code === "TOO_MANY_REQUESTS") {
				return fail(429, {
					email,
					message: "Please try again later."
				});
			}
			return fail(500, {
				email,
				message: "An unknown error occurred. Please try again later."
			});
		}

		console.log(`To ${email}: Your code is ${verificationCode}`);

		const sessionToken = generateSessionToken();
		const session = createPasswordResetSession(sessionToken, user.id, resetRequest.id);

		setPasswordResetSessionTokenCookie(event, sessionToken, session.expiresAt);

		return redirect(302, "/verify-password-reset-email");
	}
};
