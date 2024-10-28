<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData } from "./$types";

	export let form: ActionData;
</script>

<h1>Settings</h1>
<section>
	<h2>Update email address</h2>
	<form method="post" use:enhance action="?/email">
		<label for="update-email-form.email">New email</label>
		<input type="email" id="update-email-form.email" name="email" required /><br />
		<button>Send verification code</button>
		<p>{form?.email?.message ?? ""}</p>
	</form>
</section>
<section>
	<h2>Update password</h2>
	<form method="post" use:enhance action="?/password">
		<label for="update-password-form.password">Current password</label>
		<input type="password" id="update-email-form.password" name="password" autocomplete="current-password" required /><br />
		<label for="update-password-form.new-password">New password</label>
		<input
			type="password"
			id="update-password-form.new-password"
			name="new_password"
			autocomplete="new-password"
			required
		/><br />
		<button>Update</button>
		<p>{form?.password?.message ?? ""}</p>
	</form>
</section>
