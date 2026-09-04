import { describe, expect, test } from "bun:test"
import { EditDeleteActions } from "@/components/shared/edit-delete-actions"

describe("shared VPN and subscription actions", () => {
  test("both buttons use the VPN geometry, with danger styling only for enabled deletion", () => {
    const actions = EditDeleteActions({
      onEdit: () => {},
      onDelete: () => {},
      editTitle: "Edit",
      deleteTitle: "Delete",
    })
    const [edit, remove] = actions.props.children
    for (const button of [edit, remove]) {
      expect(button.props.className).toContain(
        "keen-row-action size-8 rounded-[4px]"
      )
      expect(button.props.variant).toBe("outline")
      expect(button.props.type).toBe("button")
    }
    expect(remove.props.className).toContain("keen-row-action--danger")
    const disabled = EditDeleteActions({
      onEdit: () => {},
      onDelete: () => {},
      editTitle: "Edit",
      deleteTitle: "Delete",
      deleteDisabled: true,
    }).props.children[1]
    expect(disabled.props.disabled).toBe(true)
    expect(disabled.props.className).not.toContain("keen-row-action--danger")
  })
  test("edit and delete do not also activate their containing row", () => {
    const calls: string[] = []
    const actions = EditDeleteActions({
      onEdit: () => calls.push("edit"),
      onDelete: () => calls.push("delete"),
      editTitle: "Edit",
      deleteTitle: "Delete",
    })
    for (const button of actions.props.children) {
      button.props.onClick({
        preventDefault: () => calls.push("prevent"),
        stopPropagation: () => calls.push("stop"),
      })
    }
    expect(calls).toEqual([
      "prevent",
      "stop",
      "edit",
      "prevent",
      "stop",
      "delete",
    ])
  })
})
