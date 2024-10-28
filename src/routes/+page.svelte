<script lang="ts">
	import { enhance } from "$app/forms";

	import type { PageData } from "./$types";

	export let data: PageData;
</script>

<h1>Hi, {data.user.username}!</h1>
<p>Your email address is {data.user.email}.</p>
<a href="/settings">Settings</a>
<form method="post" use:enhance>
	<button>Sign out</button>
</form>
