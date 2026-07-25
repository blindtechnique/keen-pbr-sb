import { Maximize2Icon } from "lucide-react"
import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"

import { PageHeader } from "@/components/shared/page-header"
import { UpsertCloseContext } from "@/components/shared/upsert-page-context"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { useConfigMutationPending } from "@/api/mutations"
import { useIsMobile } from "@/hooks/use-mobile"

export type UpsertPagePresentation = "page" | "dialog"

export function UpsertPage({
  title,
  description,
  cardTitle,
  cardDescription,
  children,
  dirty = false,
  onClose,
  presentation = "page",
}: {
  title: string
  description: string
  cardTitle: string
  cardDescription: string
  children: ReactNode
  dirty?: boolean
  onClose?: () => void
  presentation?: UpsertPagePresentation
}) {
  const { t } = useTranslation()
  const [location, navigate] = useLocation()
  const isMobile = useIsMobile()
  const mutationPending = useConfigMutationPending()
  const [discardDialogOpen, setDiscardDialogOpen] = useState(false)

  const close = useCallback(() => {
    if (mutationPending) {
      return
    }

    if (dirty) {
      setDiscardDialogOpen(true)
      return
    }

    onClose?.()
  }, [dirty, mutationPending, onClose])
  const closeContextValue = useMemo(() => close, [close])

  useEffect(() => {
    if (!dirty) {
      return
    }

    const preventUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault()
    }

    window.addEventListener("beforeunload", preventUnload)
    return () => window.removeEventListener("beforeunload", preventUnload)
  }, [dirty])

  const discardDialog = (
    <Dialog onOpenChange={setDiscardDialogOpen} open={discardDialogOpen}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>{t("common.unsavedChanges.title")}</DialogTitle>
          <DialogDescription>
            {t("common.unsavedChanges.description")}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button
            disabled={mutationPending}
            onClick={() => setDiscardDialogOpen(false)}
            type="button"
            variant="outline"
          >
            {t("common.unsavedChanges.continueEditing")}
          </Button>
          <Button
            disabled={mutationPending}
            onClick={() => {
              setDiscardDialogOpen(false)
              onClose?.()
            }}
            type="button"
            variant="destructive"
          >
            {t("common.unsavedChanges.discard")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )

  if (presentation === "dialog") {
    return (
      <UpsertCloseContext.Provider value={closeContextValue}>
        <Dialog
          onOpenChange={(open) => {
            if (!open) {
              close()
            }
          }}
          open
        >
          <DialogContent className="grid max-h-[calc(100dvh-2rem)] grid-rows-[auto_minmax(0,1fr)] gap-0 overflow-hidden p-0 max-sm:top-auto max-sm:bottom-0 max-sm:left-0 max-sm:max-h-[calc(100dvh-0.75rem)] max-sm:max-w-none max-sm:translate-x-0 max-sm:translate-y-0 max-sm:rounded-b-none max-sm:border-x-0 max-sm:border-b-0 sm:max-w-4xl">
            <DialogHeader className="border-b px-5 py-4 pr-12">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 space-y-1">
                  <DialogTitle className="text-xl leading-7">
                    {cardTitle}
                  </DialogTitle>
                  <DialogDescription>{cardDescription}</DialogDescription>
                </div>
                <Button
                  aria-label={t("common.openAdvancedEditor")}
                  disabled={dirty || mutationPending}
                  onClick={() => navigate(`${location}?view=page`)}
                  size={isMobile ? "icon-sm" : "sm"}
                  title={
                    dirty || mutationPending
                      ? t("common.unsavedChanges.advancedEditorDisabled")
                      : t("common.openAdvancedEditor")
                  }
                  type="button"
                  variant="outline"
                >
                  <Maximize2Icon />
                  {isMobile ? null : t("common.openAdvancedEditor")}
                </Button>
              </div>
            </DialogHeader>
            <div className="upsert-dialog-body min-h-0 overflow-y-auto px-5 pt-5">
              {children}
            </div>
          </DialogContent>
        </Dialog>
        {discardDialog}
      </UpsertCloseContext.Provider>
    )
  }

  return (
    <UpsertCloseContext.Provider value={closeContextValue}>
      <div className="space-y-5 md:space-y-6">
        <PageHeader description={description} title={title} />
        <Card size={isMobile ? "sm" : "default"}>
          <CardHeader>
            <CardTitle>{cardTitle}</CardTitle>
            <CardDescription>{cardDescription}</CardDescription>
          </CardHeader>
          <CardContent>{children}</CardContent>
        </Card>
      </div>
      {discardDialog}
    </UpsertCloseContext.Provider>
  )
}
