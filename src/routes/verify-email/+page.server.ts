import { faroe } from "$lib/server/faroe";
import { FaroeError } from "@faroe/sdk";
import { fail, redirect } from "@sveltejs/kit";
import { setUserAsEmailVerified } from "$lib/server/user";

import type { Actions, RequestEvent } from "./$types";
import type { FaroeUserEmailVerificationRequest } from "@faroe/sdk";

export async function load(event: RequestEvent) {
	if (event.locals.user === null) {
		return redirect(302, "/login");
	}
	if (event.locals.user.emailVerified) {
		return redirect(302, "/");
	}
	let rateLimited = false;
	let verificationRequest = await faroe.getUserEmailVerificationRequest(event.locals.user.faroeId);
	if (verificationRequest === null) {
		try {
			verificationRequest = await faroe.createUserEmailVerificationRequest(event.locals.user.faroeId);
			console.log(`To ${event.locals.user.email}: Your code is ${verificationRequest.code}`);
		} catch (e) {
			if (!(e instanceof FaroeError) || e.code !== "TOO_MANY_REQUESTS") {
				throw e;
			}
			rateLimited = true;
		}
	}
	return {
		user: event.locals.user,
		rateLimited
	};
}

export const actions: Actions = {
	async verify(event) {
		if (event.locals.session === null || event.locals.user === null) {
			return redirect(302, "/login");
		}
		if (event.locals.user.emailVerified) {
			return redirect(302, "/");
		}

		const formData = await event.request.formData();
		const code = formData.get("code");
		if (typeof code !== "string") {
			return fail(400, {
				verify: {
					message: "Invalid or missing fields."
				}
			});
		}
		if (code.length !== 8) {
			return fail(400, {
				verify: {
					message: "Please enter your verification code."
				}
			});
		}

		try {
			await faroe.verifyUserEmail(event.locals.user.faroeId, code);
		} catch (e) {
			if (e instanceof FaroeError && e.code === "NOT_ALLOWED") {
				const verificationRequest = await faroe.createUserEmailVerificationRequest(event.locals.user.faroeId);
				console.log(`To ${event.locals.user.email}: Your code is ${verificationRequest.code}`);
				return fail(400, {
					verify: {
						message: "Your verification code was expired. We sent a new one to your inbox."
					}
				});
			}
			if (e instanceof FaroeError && e.code === "INCORRECT_CODE") {
				return fail(400, {
					verify: {
						message: "Incorrect code."
					}
				});
			}
			if (e instanceof FaroeError && e.code === "TOO_MANY_REQUESTS") {
				return fail(429, {
					verify: {
						message: "Please try again later."
					}
				});
			}
			return fail(500, {
				verify: {
					message: "An unknown error occurred. Please try again later."
				}
			});
		}
		setUserAsEmailVerified(event.locals.user.id);
		return redirect(302, "/");
	},
	async resend(event) {
		if (event.locals.session === null || event.locals.user === null) {
			return redirect(302, "/login");
		}
		if (event.locals.user.emailVerified) {
			return redirect(302, "/");
		}

		let verificationRequest: FaroeUserEmailVerificationRequest;
		try {
			verificationRequest = await faroe.createUserEmailVerificationRequest(event.locals.user.faroeId);
		} catch (e) {
			if (e instanceof FaroeError && e.code === "TOO_MANY_REQUESTS") {
				return fail(429, {
					resend: {
						message: "Please try again later."
					}
				});
			}
			return fail(500, {
				resend: {
					message: "An unknown error occurred. Please try again later."
				}
			});
		}

		console.log(`To ${event.locals.user.email}: Your code is ${verificationRequest.code}`);
		return {
			resend: {
				message: "A new verification code was sent to your inbox."
			}
		};
	}
};
