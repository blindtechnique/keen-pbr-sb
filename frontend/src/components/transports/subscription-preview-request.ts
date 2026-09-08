// Per-dialog request identity. Resetting a TanStack mutation detaches its
// per-call callbacks, but not the promise returned by mutateAsync.
export async function runSubscriptionPreviewRequest<T>(
  active: { current: symbol | null },
  request: () => Promise<T>,
  onSuccess: (response: T) => void
): Promise<void> {
  if (active.current) return
  const token = Symbol("subscription-preview")
  active.current = token
  try {
    const response = await request()
    if (active.current === token) onSuccess(response)
  } catch {
    // The mutation already retains the error for the dialog's existing error
    // presentation. A dismissed request must not publish it into a new form.
  } finally {
    // An old request can settle after reset and a new request have started.
    if (active.current === token) active.current = null
  }
}
