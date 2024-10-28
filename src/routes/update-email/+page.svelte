<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData, PageData } from "./$types";

	export let data: PageData;
	export let form: ActionData;
</script>

<h1>Verify your new email address</h1>
<p>A verification code was sent to {data.newEmail}</p>
<form method="post" use:enhance>
	<label for="code">Code</label>
	<input id="code" name="code" />
	<br />
	<button>Verify</button>
	<p>{form?.message ?? ""}</p>
</form>
