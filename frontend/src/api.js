export async function readApiResponse(response) {
  if (response.status === 204) return null;
  const body = await response.text();
  try { return JSON.parse(body); } catch {
    if (!response.ok) return { error: body.trim() || `Request failed (${response.status})` };
    throw new Error('Server returned an invalid JSON response.');
  }
}
