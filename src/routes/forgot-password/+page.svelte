<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData } from "./$types";

	export let form: ActionData;
</script>

<h1>Forgot password?</h1>
<form method="post" use:enhance>
	<label for="email">Email</label>
	<input id="email" name="email" type="email" value={form?.email ?? ""} /><br />
	<button>Continue</button>
	<p>{form?.message ?? ""}</p>
</form>
<a href="/login">Sign in</a>
