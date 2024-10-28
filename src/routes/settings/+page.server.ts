import { fail, redirect } from "@sveltejs/kit";
import { FaroeError, verifyEmailInput, verifyPasswordInput } from "@faroe/sdk";
import { faroe } from "$lib/server/faroe";
import {
	createSession,
	generateSessionToken,
	invalidateUserSessions,
	setSessionFaroeEmailUpdateRequestId,
	setSessionTokenCookie
} from "$lib/server/session";
import { getUserFromEmail } from "$lib/server/user";

import type { Actions, RequestEvent } from "./$types";
import type { FaroeEmailUpdateRequest } from "@faroe/sdk";

export async function load(event: RequestEvent) {
	if (event.locals.user === null) {
		return redirect(302, "/login");
	}
	if (!event.locals.user.emailVerified) {
		return redirect(302, "/verify-email");
	}
	return {};
}

export const actions: Actions = {
	async password(event) {
		if (event.locals.user === null) {
			return redirect(302, "/login");
		}
		if (!event.locals.user.emailVerified) {
			return redirect(302, "/verify-email");
		}

		const formData = await event.request.formData();
		const password = formData.get("password");
		const newPassword = formData.get("new_password");
		if (typeof password !== "string" || typeof newPassword !== "string") {
			return fail(400, {
				password: {
					message: "Invalid or missing fields."
				}
			});
		}
		if (password === "" || newPassword === "") {
			return fail(400, {
				password: {
					message: "Please enter your current password and new password."
				}
			});
		}
		if (!verifyPasswordInput(password)) {
			return fail(400, {
				password: {
					message: "Please enter a valid password."
				}
			});
		}
		if (!verifyPasswordInput(newPassword)) {
			return fail(400, {
				password: {
					message: "Please enter a valid password."
				}
			});
		}

		try {
			await faroe.updateUserPassword(event.locals.user.faroeId, password, newPassword, "0.0.0.0");
		} catch (e) {
			if (e instanceof FaroeError && e.code === "INCORRECT_PASSWORD") {
				return fail(400, {
					password: {
						message: "Incorrect password."
					}
				});
			}
			if (e instanceof FaroeError && e.code === "WEAK_PASSWORD") {
				return fail(400, {
					password: {
						message: "Please use a stronger password."
					}
				});
			}
			if (e instanceof FaroeError && e.code === "TOO_MANY_REQUESTS") {
				return fail(400, {
					password: {
						message: "Please try again later."
					}
				});
			}
			return fail(500, {
				password: {
					message: "An unknown error occurred. Please try again later."
				}
			});
		}

		invalidateUserSessions(event.locals.user.id);

		const newSessionToken = generateSessionToken();
		const newSession = createSession(newSessionToken, event.locals.user.id, null);
		setSessionTokenCookie(event, newSessionToken, newSession.expiresAt);

		return {
			password: {
				message: "Password updated."
			}
		};
	},
	async email(event) {
		if (event.locals.session === null || event.locals.user === null) {
			return redirect(302, "/login");
		}
		if (!event.locals.user.emailVerified) {
			return redirect(302, "/verify-email");
		}

		const formData = await event.request.formData();
		let email = formData.get("email");
		if (typeof email !== "string") {
			return fail(400, {
				email: {
					email: "",
					message: "Invalid or missing fields."
				}
			});
		}
		email = email.toLowerCase();

		if (email === "") {
			return fail(400, {
				email: {
					email: "",
					message: "Please enter your email address."
				}
			});
		}
		if (!verifyEmailInput(email)) {
			return fail(400, {
				email: {
					email,
					message: "Please enter a valid email address."
				}
			});
		}

		const existingUser = getUserFromEmail(email);
		if (existingUser !== null) {
			return fail(400, {
				email: {
					email,
					message: "This email address is already used."
				}
			});
		}

		let updateRequest: FaroeEmailUpdateRequest;
		try {
			updateRequest = await faroe.createUserEmailUpdateRequest(event.locals.user.faroeId, email);
		} catch (e) {
			if (e instanceof FaroeError && e.code === "TOO_MANY_REQUESTS") {
				return fail(429, {
					email: {
						email,
						message: "Please try again later."
					}
				});
			}
			return fail(500, {
				email: {
					email,
					message: "An unknown error occurred. Please try again later."
				}
			});
		}

		console.log(`To ${email}: Your code is ${updateRequest.code}`);

		setSessionFaroeEmailUpdateRequestId(event.locals.session.id, updateRequest.id);

		return redirect(302, "/update-email");
	}
};
