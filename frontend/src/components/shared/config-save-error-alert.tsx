import { OperationErrorMessage } from "@/components/shared/operation-error-message"
import { Alert, AlertDescription } from "@/components/ui/alert"

export function ConfigSaveErrorAlert({ error }: { error: unknown }) {
  if (!error) {
    return null
  }

  return (
    <Alert variant="destructive">
      <AlertDescription>
        <OperationErrorMessage error={error} />
      </AlertDescription>
    </Alert>
  )
}
