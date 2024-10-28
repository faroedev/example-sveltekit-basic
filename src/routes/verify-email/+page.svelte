<script lang="ts">
	import { enhance } from "$app/forms";

	import type { ActionData, PageData } from "./$types";

	export let data: PageData;
	export let form: ActionData;
</script>

<h1>Verify your email address</h1>
{#if data.rateLimited}
	<p>Please try again later.</p>
{:else}
	<p>A verification code was sent to {data.user.email}</p>
	<form method="post" action="?/verify" use:enhance>
		<label for="code">Code</label>
		<input id="code" name="code" />
		<br />
		<button>Verify</button>
		<p>{form?.verify?.message ?? ""}</p>
	</form>
	<form method="post" action="?/resend" use:enhance>
		<button>Resend email</button>
		<p>{form?.resend?.message ?? ""}</p>
	</form>
{/if}
