import { fail, redirect } from "@sveltejs/kit";
import { faroe } from "$lib/server/faroe";
import { FaroeError } from "@faroe/sdk";
import { updateUserEmailAndSetEmailAsVerified } from "$lib/server/user";
import { deleteSessionFaroeEmailUpdateRequestId } from "$lib/server/session";

import type { Actions, RequestEvent } from "./$types";

export async function load(event: RequestEvent) {
	if (event.locals.session === null || event.locals.user === null) {
		return redirect(302, "/login");
	}
	if (!event.locals.user.emailVerified) {
		return redirect(302, "/verify-email");
	}
	if (event.locals.session.faroeEmailUpdateRequestId === null) {
		return redirect(302, "/");
	}
	const updateRequest = await faroe.getEmailUpdateRequest(event.locals.session.faroeEmailUpdateRequestId);
	if (updateRequest === null) {
		deleteSessionFaroeEmailUpdateRequestId(event.locals.session.id);
		return redirect(302, "/");
	}
	return {
		newEmail: updateRequest.email
	};
}

export const actions: Actions = {
	async default(event) {
		if (event.locals.session === null || event.locals.user === null) {
			return redirect(302, "/login");
		}
		if (event.locals.session.faroeEmailUpdateRequestId === null) {
			return redirect(302, "/");
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

		let updatedEmail: string;
		try {
			updatedEmail = await faroe.verifyNewUserEmail(event.locals.session.faroeEmailUpdateRequestId, code);
		} catch (e) {
			if (e instanceof FaroeError && e.code === "INVALID_REQUEST_ID") {
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

		updateUserEmailAndSetEmailAsVerified(event.locals.user.id, updatedEmail);
		deleteSessionFaroeEmailUpdateRequestId(event.locals.session.id);

		return redirect(302, "/");
	}
};
