import { KeenPencilIcon, KeenTrashIcon } from "@/components/shared/keen-icons"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

/** Shared VPN/subscription row actions: identical icons, hover and clicks. */
export function EditDeleteActions({
  onEdit,
  onDelete,
  editDisabled,
  deleteDisabled,
  editTitle,
  deleteTitle,
}: {
  readonly onEdit: () => void
  readonly onDelete: () => void
  readonly editDisabled?: boolean
  readonly deleteDisabled?: boolean
  readonly editTitle: string
  readonly deleteTitle: string
}) {
  return (
    <span className="keen-row-actions flex items-center gap-1">
      <Button
        aria-label={editTitle}
        className="keen-row-action size-8 rounded-[4px]"
        disabled={editDisabled}
        onClick={(event) => {
          event.preventDefault()
          event.stopPropagation()
          onEdit()
        }}
        size="icon"
        title={editTitle}
        type="button"
        variant="outline"
      >
        <KeenPencilIcon className="size-4" />
      </Button>
      <Button
        aria-label={deleteTitle}
        className={cn(
          "keen-row-action size-8 rounded-[4px]",
          !deleteDisabled && "keen-row-action--danger"
        )}
        disabled={deleteDisabled}
        onClick={(event) => {
          event.preventDefault()
          event.stopPropagation()
          onDelete()
        }}
        size="icon"
        title={deleteTitle}
        type="button"
        variant="outline"
      >
        <KeenTrashIcon className="size-4" />
      </Button>
    </span>
  )
}
