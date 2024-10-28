import {
	deletePasswordResetSessionTokenCookie,
	invalidatePasswordResetSession,
	setPasswordResetSessionAsEmailVerified,
	validatePasswordResetSessionRequest
} from "$lib/server/password-reset-session";
import { fail, redirect } from "@sveltejs/kit";
import { faroe } from "$lib/server/faroe";
import { FaroeError } from "@faroe/sdk";

import type { Actions, RequestEvent } from "./$types";

export async function load(event: RequestEvent) {
	const { session, user } = validatePasswordResetSessionRequest(event);
	if (session === null) {
		return redirect(302, "/forgot-password");
	}
	if (session.emailVerified) {
		return redirect(302, "/reset-password");
	}
	return {
		user
	};
}

export const actions: Actions = {
	async default(event) {
		const { session } = validatePasswordResetSessionRequest(event);
		if (session === null) {
			return redirect(302, "/forgot-password");
		}
        if (session.emailVerified) {
            return redirect(302, "/reset-password");
        }

		const formData = await event.request.formData();
		const code = formData.get("code");
		if (typeof code !== "string") {
			return fail(400, {
				message: "Invalid or missing fields."
			});
		}
		if (code.length !== 8) {
			return fail(400, {
				message: "Please enter your verification code."
			});
		}

		try {
			await faroe.verifyPasswordResetRequestEmail(session.faroeRequestId, code, "0.0.0.0");
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_FOUND") {
				invalidatePasswordResetSession(session.id);
				deletePasswordResetSessionTokenCookie(event);
				return fail(400, {
					message: "Please restart the process."
				});
			}
			if (e instanceof FaroeError && e.code === "INCORRECT_CODE") {
				return fail(400, {
					message: "Incorrect code."
				});
			}
			if (e instanceof FaroeError && e.code === "TOO_MANY_REQUESTS") {
				return fail(400, {
					message: "Please restart the process."
				});
			}
			return fail(500, {
				message: "An unknown error occurred. Please try again later."
			});
		}

		setPasswordResetSessionAsEmailVerified(session.id);

		return redirect(302, "/reset-password");
	}
};
