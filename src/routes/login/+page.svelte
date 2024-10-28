<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData } from "./$types";

	export let form: ActionData;
</script>

<h1>Sign in</h1>
<form method="post" use:enhance>
	<label for="email">Email</label>
	<input id="email" name="email" type="email" value={form?.email ?? ""} /><br />
	<label for="password">Password</label>
	<input id="password" name="password" type="password" /><br />
	<button>Continue</button>
	<p>{form?.message ?? ""}</p>
</form>
<a href="/signup">Create an account</a>
<a href="/forgot-password">Forgot password?</a>
