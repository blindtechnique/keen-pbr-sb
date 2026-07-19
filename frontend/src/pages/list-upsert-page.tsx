import { useForm } from "@tanstack/react-form"
import { useQueryClient } from "@tanstack/react-query"
import { useStore } from "@tanstack/react-store"
import {
  CheckCircle2Icon,
  CircleIcon,
  CloudIcon,
  FileTextIcon,
  ScrollTextIcon,
  SparklesIcon,
} from "lucide-react"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { useLocation } from "wouter"
import { toast } from "sonner"

import type { ApiError } from "@/api/client"
import type { DnsRule } from "@/api/generated/model/dnsRule"
import type { ConfigObject } from "@/api/generated/model/configObject"
import type { ListConfig } from "@/api/generated/model/listConfig"
import type { Outbound } from "@/api/generated/model/outbound"
import { usePostConfigMutation } from "@/api/mutations"
import { queryKeys } from "@/api/query-keys"
import { useGetConfig } from "@/api/queries"
import { selectConfig } from "@/api/selectors"
import { OutboundSelect } from "@/components/shared/outbound-select"
import {
  Field,
  FieldContent,
  FieldGroup,
  FieldHint,
  FieldLabel,
} from "@/components/shared/field"
import { CodeEditor } from "@/components/shared/code-editor"
import { TemplatePicker } from "@/components/lists/template-picker"
import { ServerValidationAlert } from "@/components/shared/server-validation-alert"
import { UpsertPage } from "@/components/shared/upsert-page"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { ButtonGroup } from "@/components/ui/button-group"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  clearFormServerErrors,
  setFormServerErrors,
  splitFormApiErrors,
} from "@/lib/form-api-errors"
import { cn } from "@/lib/utils"
import { getTagNameValidationError } from "@/lib/tag-name-validation"
import { useIsMobile } from "@/hooks/use-mobile"

type ListDraft = {
  name: string
  ttlMs: string
  detour: string
  domains: string
  ipCidrs: string
  url: string
  file: string
}

type ListSourceGroup = "url" | "file" | "inline"
type QuickSetup = {
  createRouteRule: boolean
  routeOutbound: string
  createDnsRule: boolean
  dnsServer: string
}
type ListFieldName = (typeof LIST_FIELD_NAMES)[keyof typeof LIST_FIELD_NAMES]

const LIST_SOURCE_GROUPS: ListSourceGroup[] = ["url", "file", "inline"]
const DEFAULT_SOURCE_GROUP: ListSourceGroup = "url"
const LIST_FIELD_NAMES = {
  name: "name",
  ttlMs: "ttlMs",
  detour: "detour",
  domains: "domains",
  ipCidrs: "ipCidrs",
  url: "url",
  file: "file",
} as const
const LIST_SOURCE_GROUP_ICONS = {
  url: CloudIcon,
  file: FileTextIcon,
  inline: ScrollTextIcon,
} satisfies Record<ListSourceGroup, typeof CloudIcon>
const LIST_SOURCE_GROUP_FIELDS = {
  url: [LIST_FIELD_NAMES.url],
  file: [LIST_FIELD_NAMES.file],
  inline: [LIST_FIELD_NAMES.domains, LIST_FIELD_NAMES.ipCidrs],
} satisfies Record<ListSourceGroup, ListFieldName[]>

const sampleNewList: ListDraft = {
  name: "",
  ttlMs: "7200000",
  detour: "",
  domains: "",
  ipCidrs: "",
  url: "",
  file: "",
}

export function ListUpsertPage({
  mode,
  listId,
}: {
  mode: "create" | "edit"
  listId?: string
}) {
  const { t } = useTranslation()
  const [, navigate] = useLocation()
  const configQuery = useGetConfig()
  const loadedConfig = selectConfig(configQuery.data)

  if (!loadedConfig) {
    return (
      <UpsertPage
        cardDescription={t("pages.listUpsert.cardDescription")}
        cardTitle={
          mode === "create"
            ? t("pages.listUpsert.createTitle")
            : t("pages.listUpsert.editTitle")
        }
        description={t("pages.listUpsert.description")}
        title={
          mode === "create"
            ? t("pages.listUpsert.createTitle")
            : t("pages.listUpsert.editTitle")
        }
      >
        <div className="space-y-3">
          <div className="h-8 rounded-lg bg-muted" />
          <div className="h-24 rounded-lg bg-muted" />
          <div className="h-8 rounded-lg bg-muted" />
          <div className="h-8 rounded-lg bg-muted" />
        </div>
      </UpsertPage>
    )
  }

  const listsMap = loadedConfig.lists ?? {}
  const draft =
    mode === "edit"
      ? getDraftFromMapEntry(listId, listId ? listsMap[listId] : undefined)
      : sampleNewList

  if (mode === "edit" && !draft) {
    return (
      <UpsertPage
        cardDescription={t("pages.listUpsert.missing.cardDescription")}
        cardTitle={t("pages.listUpsert.missing.cardTitle")}
        description={t("pages.listUpsert.missing.description")}
        title={t("pages.listUpsert.editTitle")}
      >
        <div className="flex justify-end">
          <Button onClick={() => navigate("/lists")} variant="outline">
            {t("pages.listUpsert.missing.back")}
          </Button>
        </div>
      </UpsertPage>
    )
  }

  return (
    <UpsertPage
      cardDescription={t("pages.listUpsert.cardDescription")}
      cardTitle={
        mode === "create"
          ? t("pages.listUpsert.createTitle")
          : t("pages.listUpsert.editCardTitle", {
              name: draft?.name ?? t("pages.listUpsert.fallbackName"),
            })
      }
      description={t("pages.listUpsert.description")}
      title={
        mode === "create"
          ? t("pages.listUpsert.createTitle")
          : t("pages.listUpsert.editTitle")
      }
    >
      <ListForm
        key={`${mode}:${listId ?? "new"}`}
        outbounds={loadedConfig.outbounds ?? []}
        draft={draft ?? sampleNewList}
        existingListNames={Object.keys(listsMap)}
        listId={listId}
        loadedConfig={loadedConfig}
        mode={mode}
      />
    </UpsertPage>
  )
}

function ListForm({
  mode,
  outbounds,
  draft,
  existingListNames,
  listId,
  loadedConfig,
}: {
  mode: "create" | "edit"
  outbounds: Outbound[]
  draft: ListDraft
  existingListNames: string[]
  listId?: string
  loadedConfig: ConfigObject
}) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [, navigate] = useLocation()
  const [activeSourceGroups, setActiveSourceGroups] = useState<
    ListSourceGroup[]
  >(() => getActiveSourceGroupsFromDraft(draft))
  const postConfigMutation = usePostConfigMutation()
  const isMobile = useIsMobile()
  const dnsServerTags = (loadedConfig.dns?.servers ?? []).map(
    (server) => server.tag
  )
  const [quickSetup, setQuickSetup] = useState<QuickSetup>({
    createRouteRule: false,
    routeOutbound: "",
    createDnsRule: false,
    dnsServer: dnsServerTags[0] ?? "",
  })
  // DNS rules are edited where they belong — next to the list they apply to —
  // instead of in a separate section listing every rule at once.
  const currentDnsServer =
    (loadedConfig.dns?.rules ?? []).find((rule) =>
      (rule.list ?? []).includes(listId ?? "")
    )?.server ?? ""
  const [dnsServerForList, setDnsServerForList] = useState(currentDnsServer)
  const [templatePickerOpen, setTemplatePickerOpen] = useState(false)

  const form = useForm({
    defaultValues: draft,
    validators: {
      onSubmitAsync: async ({ value }) => {
        clearFormServerErrors(form)
        if (
          mode === "create" &&
          quickSetup.createRouteRule &&
          !quickSetup.routeOutbound
        ) {
          toast.error(t("pages.listUpsert.quickSetup.routeRequired"), {
            richColors: true,
          })
          return undefined
        }
        if (
          mode === "create" &&
          quickSetup.createDnsRule &&
          !quickSetup.dnsServer
        ) {
          toast.error(t("pages.listUpsert.quickSetup.dnsRequired"), {
            richColors: true,
          })
          return undefined
        }
        const updatedConfig = buildUpdatedConfigForListUpsert(
          loadedConfig,
          mode,
          value,
          listId,
          mode === "create" ? quickSetup : undefined,
          mode === "edit" ? dnsServerForList : undefined
        )

        try {
          await postConfigMutation.mutateAsync({ data: updatedConfig })
          toast.success(
            mode === "create"
              ? t("pages.listUpsert.messages.created")
              : t("pages.listUpsert.messages.updated")
          )
          clearFormServerErrors(form)
          await Promise.all([
            queryClient.invalidateQueries({ queryKey: queryKeys.config() }),
            queryClient.invalidateQueries({ queryKey: queryKeys.dnsTest() }),
          ])
          navigate("/lists")
          return undefined
        } catch (error) {
          const apiError = error as ApiError
          const result = splitFormApiErrors({
            error: apiError,
            fieldNames: Object.values(LIST_FIELD_NAMES),
            resolvePath: (path) =>
              resolveListFieldPath(path, value.name || draft.name),
          })

          setFormServerErrors(form, {
            form: result.formError ?? undefined,
            fields: result.fieldErrors,
            unmapped: result.unmappedErrors,
          })

          if (result.formError) {
            toast.error(result.formError, { richColors: true })
          }

          return {
            form: result.formError ?? undefined,
            fields: result.fieldErrors,
          }
        }
      },
    },
  })

  const apiErrorMessage = useStore(
    form.store,
    (state) =>
      (state.errorMap.onServer as { form?: string } | undefined)?.form ?? null
  )
  const unmappedServerErrors = useStore(
    form.store,
    (state) =>
      (
        state.errorMap.onServer as
          | {
              unmapped?: { path: string; message: string }[]
            }
          | undefined
      )?.unmapped ?? []
  )

  const isCreate = mode === "create"

  const handleSourceGroupSelect = (group: ListSourceGroup) => {
    const currentValues = form.state.values
    const filledActiveGroups = activeSourceGroups.filter((sourceGroup) =>
      isSourceGroupPopulated(sourceGroup, currentValues)
    )
    const groupsToClear = filledActiveGroups.filter(
      (sourceGroup) => sourceGroup !== group
    )

    if (
      groupsToClear.length === 0 &&
      activeSourceGroups.length === 1 &&
      activeSourceGroups[0] === group
    ) {
      return
    }

    if (
      groupsToClear.length > 0 &&
      !window.confirm(t("pages.listUpsert.sourceSwitcher.confirmChange"))
    ) {
      return
    }

    setActiveSourceGroups([group])
    clearFormServerErrors(form)

    for (const sourceGroup of LIST_SOURCE_GROUPS) {
      if (sourceGroup === group) {
        continue
      }

      for (const fieldName of LIST_SOURCE_GROUP_FIELDS[sourceGroup]) {
        form.setFieldValue(fieldName, "")
      }
    }

    if (group !== "inline") {
      form.setFieldValue(LIST_FIELD_NAMES.domains, "")
      form.setFieldValue(LIST_FIELD_NAMES.ipCidrs, "")
    }
  }

  return (
    <form
      className="space-y-6"
      onSubmit={(event) => {
        event.preventDefault()
        form.handleSubmit()
      }}
    >
      <Card>
        <CardHeader>
          <CardTitle>{t("pages.listUpsert.common.title")}</CardTitle>
          <CardDescription>
            {t("pages.listUpsert.common.description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <form.Field
              name={LIST_FIELD_NAMES.name}
              validators={{
                onChange: ({ value }) =>
                  getListNameError(
                    value,
                    existingListNames,
                    isCreate ? undefined : draft.name,
                    t
                  ) ?? undefined,
              }}
            >
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)

                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor="list-name">
                      {t("pages.listUpsert.fields.name")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        disabled={!isCreate}
                        id="list-name"
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.listUpsert.fields.nameHint")}
                        error={error ?? null}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>

            <form.Field
              name={LIST_FIELD_NAMES.ttlMs}
              validators={{
                onMount: ({ value }) => getTtlError(value, t) ?? undefined,
                onChange: ({ value }) => getTtlError(value, t) ?? undefined,
              }}
            >
              {(field) => {
                const error = getFirstFieldError(field.state.meta.errors)

                return (
                  <Field invalid={Boolean(error)}>
                    <FieldLabel htmlFor="list-ttl-ms">
                      {t("pages.listUpsert.fields.ttlMs")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        aria-invalid={Boolean(error)}
                        id="list-ttl-ms"
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.listUpsert.fields.ttlMsHint")}
                        error={error ?? null}
                      />
                    </FieldContent>
                  </Field>
                )
              }}
            </form.Field>
          </FieldGroup>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("pages.listUpsert.sourceSwitcher.title")}</CardTitle>
          <CardDescription>
            {t("pages.listUpsert.sourceSwitcher.description")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ButtonGroup
            className="w-full data-[orientation=vertical]:h-fit [&>[data-slot=button]]:flex-1 data-[orientation=vertical]:[&>[data-slot=button]]:w-full data-[orientation=vertical]:[&>[data-slot=button]]:justify-start data-[orientation=vertical]:[&>[data-slot=button]]:px-3"
            orientation={isMobile ? "vertical" : "horizontal"}
          >
            {LIST_SOURCE_GROUPS.map((group) => {
              const Icon = LIST_SOURCE_GROUP_ICONS[group]
              const active = activeSourceGroups.includes(group)

              return (
                <Button
                  aria-pressed={active}
                  className={cn(
                    isMobile && "h-auto min-h-11 py-2.5",
                    active &&
                      "border-border bg-secondary text-secondary-foreground hover:bg-secondary/80"
                  )}
                  key={group}
                  onClick={() => handleSourceGroupSelect(group)}
                  size={isMobile ? "default" : "sm"}
                  type="button"
                  variant="outline"
                >
                  {isMobile ? (
                    active ? (
                      <CheckCircle2Icon className="size-4 text-primary" />
                    ) : (
                      <CircleIcon className="size-4 text-muted-foreground" />
                    )
                  ) : null}
                  <Icon className="size-4" />
                  {t(`pages.listUpsert.sourceGroups.${group}.button`)}
                </Button>
              )
            })}
          </ButtonGroup>
        </CardContent>
      </Card>

      {activeSourceGroups.includes("url") ? (
        <Card>
          <CardHeader>
            <CardTitle>
              {t("pages.listUpsert.sourceGroups.url.title")}
            </CardTitle>
            <CardDescription>
              {t("pages.listUpsert.sourceGroups.url.description")}
            </CardDescription>
            <CardAction>
              <Button
                onClick={() => setTemplatePickerOpen(true)}
                size="sm"
                type="button"
                variant="outline"
              >
                <SparklesIcon className="mr-1 h-4 w-4" />
                {t("pages.listUpsert.templates.button")}
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <form.Field name={LIST_FIELD_NAMES.url}>
                {(field) => (
                  <Field>
                    <FieldLabel htmlFor="list-url">
                      {t("pages.listUpsert.fields.url")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        id="list-url"
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.listUpsert.fields.urlHint")}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>

              <form.Field name={LIST_FIELD_NAMES.detour}>
                {(field) => {
                  const error = getFirstFieldError(field.state.meta.errors)

                  return (
                    <Field invalid={Boolean(error)}>
                      <FieldLabel>
                        {t("pages.listUpsert.fields.detour")}
                      </FieldLabel>
                      <FieldContent>
                        <OutboundSelect
                          allowEmpty
                          ariaInvalid={Boolean(error)}
                          emptyLabel={t("pages.listUpsert.fields.detourEmpty")}
                          onValueChange={field.handleChange}
                          outbounds={outbounds}
                          placeholder={t(
                            "pages.listUpsert.fields.detourPlaceholder"
                          )}
                          value={field.state.value}
                        />
                        <FieldHint
                          description={t("pages.listUpsert.fields.detourHint")}
                          error={error}
                        />
                      </FieldContent>
                    </Field>
                  )
                }}
              </form.Field>
            </FieldGroup>
          </CardContent>
        </Card>
      ) : null}

      {activeSourceGroups.includes("file") ? (
        <Card>
          <CardHeader>
            <CardTitle>
              {t("pages.listUpsert.sourceGroups.file.title")}
            </CardTitle>
            <CardDescription>
              {t("pages.listUpsert.sourceGroups.file.description")}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <form.Field name={LIST_FIELD_NAMES.file}>
                {(field) => (
                  <Field>
                    <FieldLabel htmlFor="list-file">
                      {t("pages.listUpsert.fields.file")}
                    </FieldLabel>
                    <FieldContent>
                      <Input
                        id="list-file"
                        onBlur={field.handleBlur}
                        onChange={(event) =>
                          field.handleChange(event.target.value)
                        }
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.listUpsert.fields.fileHint")}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>
            </FieldGroup>
          </CardContent>
        </Card>
      ) : null}

      {activeSourceGroups.includes("inline") ? (
        <Card>
          <CardHeader>
            <CardTitle>
              {t("pages.listUpsert.sourceGroups.inline.title")}
            </CardTitle>
            <CardDescription>
              {t("pages.listUpsert.sourceGroups.inline.description")}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <form.Field name={LIST_FIELD_NAMES.domains}>
                {(field) => (
                  <Field>
                    <FieldLabel htmlFor="list-domains">
                      {t("pages.listUpsert.fields.domains")}
                    </FieldLabel>
                    <FieldContent>
                      <CodeEditor
                        className="min-h-24"
                        id="list-domains"
                        onBlur={field.handleBlur}
                        onChange={(next) => field.handleChange(next)}
                        syntax="list"
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.listUpsert.fields.domainsHint")}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>
              <form.Field name={LIST_FIELD_NAMES.ipCidrs}>
                {(field) => (
                  <Field>
                    <FieldLabel htmlFor="list-ip-cidrs">
                      {t("pages.listUpsert.fields.ipCidrs")}
                    </FieldLabel>
                    <FieldContent>
                      <CodeEditor
                        className="min-h-24"
                        id="list-ip-cidrs"
                        onBlur={field.handleBlur}
                        onChange={(next) => field.handleChange(next)}
                        syntax="list"
                        value={field.state.value}
                      />
                      <FieldHint
                        description={t("pages.listUpsert.fields.ipCidrsHint")}
                      />
                    </FieldContent>
                  </Field>
                )}
              </form.Field>
            </FieldGroup>
          </CardContent>
        </Card>
      ) : null}

      {!isCreate ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("pages.listUpsert.dnsRule.title")}</CardTitle>
            <CardDescription>
              {t("pages.listUpsert.dnsRule.description")}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Select
              onValueChange={(value) => setDnsServerForList(value ?? "")}
              value={dnsServerForList || NO_DNS_RULE}
            >
              <SelectTrigger>
                <SelectValue
                  placeholder={t("pages.listUpsert.quickSetup.selectDnsServer")}
                />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value={NO_DNS_RULE}>
                    {t("pages.listUpsert.dnsRule.none")}
                  </SelectItem>
                  {dnsServerTags.map((tag) => (
                    <SelectItem key={tag} value={tag}>
                      {tag}
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
            {dnsServerTags.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {t("pages.listUpsert.quickSetup.noDnsServers")}
              </p>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      <TemplatePicker
        onOpenChange={setTemplatePickerOpen}
        onSelect={(template) => {
          form.setFieldValue(LIST_FIELD_NAMES.url, template.url)
          if (isCreate && !form.getFieldValue(LIST_FIELD_NAMES.name)) {
            form.setFieldValue(LIST_FIELD_NAMES.name, template.id)
          }
        }}
        open={templatePickerOpen}
      />

      {isCreate ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("pages.listUpsert.quickSetup.title")}</CardTitle>
            <CardDescription>
              {t("pages.listUpsert.quickSetup.description")}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <Checkbox
                  checked={quickSetup.createRouteRule}
                  id="list-create-route-rule"
                  onCheckedChange={(checked) =>
                    setQuickSetup((current) => ({
                      ...current,
                      createRouteRule: checked === true,
                    }))
                  }
                />
                <FieldLabel
                  className="cursor-pointer"
                  htmlFor="list-create-route-rule"
                >
                  {t("pages.listUpsert.quickSetup.createRouteRule")}
                </FieldLabel>
              </div>
              {quickSetup.createRouteRule ? (
                <OutboundSelect
                  onValueChange={(value) =>
                    setQuickSetup((current) => ({
                      ...current,
                      routeOutbound: value,
                    }))
                  }
                  outbounds={outbounds}
                  placeholder={t("pages.listUpsert.quickSetup.selectOutbound")}
                  value={quickSetup.routeOutbound}
                />
              ) : null}
            </div>

            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <Checkbox
                  checked={quickSetup.createDnsRule}
                  disabled={dnsServerTags.length === 0}
                  id="list-create-dns-rule"
                  onCheckedChange={(checked) =>
                    setQuickSetup((current) => ({
                      ...current,
                      createDnsRule: checked === true,
                    }))
                  }
                />
                <FieldLabel
                  className="cursor-pointer"
                  htmlFor="list-create-dns-rule"
                >
                  {t("pages.listUpsert.quickSetup.createDnsRule")}
                </FieldLabel>
              </div>
              {quickSetup.createDnsRule ? (
                <Select
                  onValueChange={(value) =>
                    setQuickSetup((current) => ({
                      ...current,
                      dnsServer: value ?? "",
                    }))
                  }
                  value={quickSetup.dnsServer}
                >
                  <SelectTrigger>
                    <SelectValue
                      placeholder={t(
                        "pages.listUpsert.quickSetup.selectDnsServer"
                      )}
                    />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      {dnsServerTags.map((tag) => (
                        <SelectItem key={tag} value={tag}>
                          {tag}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  </SelectContent>
                </Select>
              ) : null}
              {dnsServerTags.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t("pages.listUpsert.quickSetup.noDnsServers")}
                </p>
              ) : null}
            </div>

            <p className="text-sm text-muted-foreground">
              {t("pages.listUpsert.quickSetup.manualHint")}
            </p>
          </CardContent>
        </Card>
      ) : null}

      {apiErrorMessage ? (
        <Alert className="border-destructive/30 bg-destructive/5 text-destructive">
          <AlertDescription className="whitespace-pre-wrap">
            {apiErrorMessage}
          </AlertDescription>
        </Alert>
      ) : null}

      <ServerValidationAlert errors={unmappedServerErrors} />

      <div className="flex justify-end gap-3">
        <Button
          onClick={() => navigate("/lists")}
          size="xl"
          type="button"
          variant="outline"
        >
          {t("common.cancel")}
        </Button>
        <form.Subscribe
          selector={(state) => ({
            canSubmit: state.canSubmit,
            isPristine: state.isPristine,
          })}
        >
          {({ canSubmit, isPristine }) => (
            <Button
              disabled={
                postConfigMutation.isPending || isPristine || !canSubmit
              }
              size="xl"
              type="submit"
            >
              {postConfigMutation.isPending
                ? t("pages.listUpsert.actions.saving")
                : mode === "create"
                  ? t("pages.listUpsert.actions.create")
                  : t("pages.listUpsert.actions.save")}
            </Button>
          )}
        </form.Subscribe>
      </div>
    </form>
  )
}

function getActiveSourceGroupsFromDraft(draft: ListDraft): ListSourceGroup[] {
  const populatedGroups: ListSourceGroup[] = []

  if (draft.url.trim()) {
    populatedGroups.push("url")
  }

  if (draft.file.trim()) {
    populatedGroups.push("file")
  }

  if (
    splitLines(draft.domains).length > 0 ||
    splitLines(draft.ipCidrs).length > 0
  ) {
    populatedGroups.push("inline")
  }

  return populatedGroups.length > 0 ? populatedGroups : [DEFAULT_SOURCE_GROUP]
}

function isSourceGroupPopulated(group: ListSourceGroup, draft: ListDraft) {
  if (group === "inline") {
    return (
      splitLines(draft.domains).length > 0 ||
      splitLines(draft.ipCidrs).length > 0
    )
  }

  return draft[group].trim().length > 0
}

function getDraftFromMapEntry(
  name: string | undefined,
  listConfig?: ListConfig
): ListDraft | null {
  if (!name || !listConfig) {
    return null
  }

  return {
    name,
    ttlMs: String(listConfig.ttl_ms ?? 0),
    detour: listConfig.detour ?? "",
    domains: (listConfig.domains ?? []).join("\n"),
    ipCidrs: (listConfig.ip_cidrs ?? []).join("\n"),
    url: listConfig.url ?? "",
    file: listConfig.file ?? "",
  }
}

const NO_DNS_RULE = "__none__"

function buildUpdatedConfigForListUpsert(
  config: ConfigObject,
  mode: "create" | "edit",
  nextDraft: ListDraft,
  originalName?: string,
  quickSetup?: QuickSetup,
  dnsServerForList?: string
): ConfigObject {
  const nextLists = { ...(config.lists ?? {}) }
  const trimmedName = nextDraft.name.trim()
  const resolvedName =
    mode === "edit" ? (originalName?.trim() ?? trimmedName) : trimmedName
  const nextListConfig = getListConfigFromDraft(nextDraft)

  nextLists[resolvedName] = nextListConfig

  const updated: ConfigObject = {
    ...config,
    lists: nextLists,
  }
  if (quickSetup?.createRouteRule && quickSetup.routeOutbound) {
    updated.route = {
      ...(config.route ?? {}),
      rules: [
        ...(config.route?.rules ?? []),
        {
          enabled: true,
          list: [resolvedName],
          outbound: quickSetup.routeOutbound,
        },
      ],
    }
  }
  if (quickSetup?.createDnsRule && quickSetup.dnsServer) {
    updated.dns = {
      ...(config.dns ?? {}),
      rules: [
        ...(config.dns?.rules ?? []),
        {
          enabled: true,
          list: [resolvedName],
          server: quickSetup.dnsServer,
          allow_domain_rebinding: false,
        },
      ],
    }
  }

  if (dnsServerForList !== undefined) {
    updated.dns = {
      ...(config.dns ?? {}),
      rules: applyDnsRuleForList(
        config.dns?.rules ?? [],
        resolvedName,
        dnsServerForList === NO_DNS_RULE ? "" : dnsServerForList
      ),
    }
  }
  return updated
}

/**
 * Keeps at most one DNS rule per list. An empty server drops the binding; a
 * rule shared with other lists only loses this list instead of disappearing.
 */
function applyDnsRuleForList(
  rules: DnsRule[],
  listName: string,
  server: string
): DnsRule[] {
  const next: DnsRule[] = []
  let applied = false

  for (const rule of rules) {
    const lists = rule.list ?? []
    if (!lists.includes(listName)) {
      next.push(rule)
      continue
    }

    if (lists.length > 1) {
      next.push({ ...rule, list: lists.filter((item) => item !== listName) })
      continue
    }

    if (server) {
      next.push({ ...rule, server })
      applied = true
    }
  }

  if (server && !applied) {
    next.push({
      enabled: true,
      list: [listName],
      server,
      allow_domain_rebinding: false,
    })
  }

  return next
}

function getListConfigFromDraft(draft: ListDraft): ListConfig {
  const domains = splitLines(draft.domains)
  const ipCidrs = splitLines(draft.ipCidrs)
  const trimmedUrl = draft.url.trim()
  const trimmedFile = draft.file.trim()
  const trimmedDetour = draft.detour.trim()
  const ttlMs = Number.parseInt(draft.ttlMs.trim(), 10)

  const listConfig: ListConfig = {}
  listConfig.ttl_ms = Number.isNaN(ttlMs) ? 0 : ttlMs

  if (trimmedUrl) {
    listConfig.url = trimmedUrl
  }

  if (trimmedFile) {
    listConfig.file = trimmedFile
  }

  if (domains.length > 0) {
    listConfig.domains = domains
  }

  if (ipCidrs.length > 0) {
    listConfig.ip_cidrs = ipCidrs
  }

  if (trimmedDetour) {
    listConfig.detour = trimmedDetour
  }

  return listConfig
}

function splitLines(value: string) {
  return value
    .split("\n")
    .map((entry) => entry.trim())
    .filter(Boolean)
}

function getFirstFieldError(errors: unknown[]) {
  const firstError = errors[0]
  return typeof firstError === "string" ? firstError : null
}

function getListNameError(
  value: string,
  existingListNames: string[],
  currentName?: string,
  t?: (key: string) => string
) {
  const trimmedName = value.trim()
  const duplicateError =
    existingListNames.includes(trimmedName) && trimmedName !== currentName
      ? (t?.("pages.listUpsert.validation.duplicateName") ??
        "A list with this name already exists.")
      : null

  return getTagNameValidationError(value, {
    requiredError:
      t?.("pages.listUpsert.validation.nameRequired") ?? "Name is required.",
    invalidError:
      t?.("common.validation.tagNamePattern") ??
      "Must match [a-z][a-z0-9_]{0,23}.",
    duplicateError,
  })
}

function getTtlError(value: string, t?: (key: string) => string) {
  const trimmed = value.trim()
  if (!/^\d+$/.test(trimmed)) {
    return (
      t?.("pages.listUpsert.validation.invalidTtl") ??
      "TTL must be a non-negative integer."
    )
  }

  return null
}

function resolveListFieldPath(
  path: string,
  name: string
): ListFieldName | undefined {
  const normalizedName = name.trim()

  if (path === "lists") {
    return LIST_FIELD_NAMES.name
  }

  if (normalizedName && path === `lists.${normalizedName}`) {
    return LIST_FIELD_NAMES.name
  }

  if (normalizedName && path === `lists.${normalizedName}.ttl_ms`) {
    return LIST_FIELD_NAMES.ttlMs
  }

  if (normalizedName && path === `lists.${normalizedName}.domains`) {
    return LIST_FIELD_NAMES.domains
  }

  if (normalizedName && path === `lists.${normalizedName}.ip_cidrs`) {
    return LIST_FIELD_NAMES.ipCidrs
  }

  if (normalizedName && path === `lists.${normalizedName}.url`) {
    return LIST_FIELD_NAMES.url
  }

  if (normalizedName && path === `lists.${normalizedName}.file`) {
    return LIST_FIELD_NAMES.file
  }

  if (normalizedName && path === `lists.${normalizedName}.detour`) {
    return LIST_FIELD_NAMES.detour
  }

  return undefined
}
