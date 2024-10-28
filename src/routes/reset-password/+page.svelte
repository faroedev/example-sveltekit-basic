<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData } from "./$types";

	export let form: ActionData;
</script>

<h1>Reset your password</h1>
<form method="post" use:enhance>
	<label for="password">New password</label>
	<input id="password" name="password" type="password" autocomplete="new-password" /><br />
	<button>Reset</button>
	<p>{form?.message ?? ""}</p>
</form>
