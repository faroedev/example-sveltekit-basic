import {
	deletePasswordResetSessionTokenCookie,
	invalidatePasswordResetSession,
	validatePasswordResetSessionRequest
} from "$lib/server/password-reset-session";
import { fail, redirect } from "@sveltejs/kit";
import { FaroeError, verifyPasswordInput } from "@faroe/sdk";
import { faroe } from "$lib/server/faroe";
import { setUserAsEmailVerified } from "$lib/server/user";
import { createSession, generateSessionToken, setSessionTokenCookie } from "$lib/server/session";

import type { Actions, RequestEvent } from "./$types";

export async function load(event: RequestEvent) {
	const { session } = validatePasswordResetSessionRequest(event);
	if (session === null) {
		return redirect(302, "/forgot-password");
	}
	if (!session.emailVerified) {
		return redirect(302, "/verify-password-reset-email");
	}
	return {};
}

export const actions: Actions = {
	async default(event) {
		const { session: passwordResetSession, user } = validatePasswordResetSessionRequest(event);
		if (passwordResetSession === null) {
			return redirect(302, "/forgot-password");
		}
        if (!passwordResetSession.emailVerified) {
            return redirect(302, "/verify-password-reset-email");
        }

		const formData = await event.request.formData();
		const password = formData.get("password");
		if (typeof password !== "string") {
			return fail(400, {
				message: "Invalid or missing fields."
			});
		}
		if (password === "") {
			return fail(400, {
				message: "Please enter your new password."
			});
		}
		if (!verifyPasswordInput(password)) {
			return fail(400, {
				message: "Please enter a valid password."
			});
		}

		try {
			await faroe.resetUserPassword(passwordResetSession.faroeRequestId, password, "0.0.0.0");
		} catch (e) {
			if (e instanceof FaroeError && e.code === "INVALID_REQUEST_ID") {
				return fail(400, {
					message: "Please restart the process."
				});
			}
			if (e instanceof FaroeError && e.code === "WEAK_PASSWORD") {
				return fail(400, {
					message: "Please use a stronger password."
				});
			}
			if (e instanceof FaroeError && e.code === "TOO_MANY_REQUESTS") {
				return fail(400, {
					message: "Please try again later."
				});
			}
			return fail(500, {
				message: "An unknown error occurred. Please try again."
			});
		}

		setUserAsEmailVerified(user.id);
		invalidatePasswordResetSession(passwordResetSession.id);
		deletePasswordResetSessionTokenCookie(event);

		const sessionToken = generateSessionToken();
		const session = createSession(sessionToken, user.id, null);
		setSessionTokenCookie(event, sessionToken, session.expiresAt);

		return redirect(302, "/");
	}
};
