import { redirect } from "@sveltejs/kit";
import { deleteSessionTokenCookie, invalidateSession } from "$lib/server/session";

import type { Actions, RequestEvent } from "./$types";

export async function load(event: RequestEvent) {
	if (event.locals.user === null) {
		return redirect(302, "/login");
	}
	if (!event.locals.user.emailVerified) {
		return redirect(302, "/verify-email");
	}
	return {
		user: event.locals.user
	};
}

export const actions: Actions = {
	async default(event) {
		if (event.locals.session === null) {
			return redirect(302, "/login");
		}
		invalidateSession(event.locals.session.id);
		deleteSessionTokenCookie(event);
		return redirect(302, "/login");
	}
};
