import { cva, type VariantProps } from "class-variance-authority"
import { useMemo, type ReactNode } from "react"

import { Label } from "@/components/ui/label"
import { cn } from "@/lib/utils"

function FieldGroup({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("group/field-group flex w-full flex-col gap-6", className)}
      data-slot="field-group"
      {...props}
    />
  )
}

const fieldVariants = cva("group/field flex w-full gap-2", {
  variants: {
    orientation: {
      vertical: "flex-col",
      horizontal:
        "flex-row items-start [&>[data-slot=field-label]]:flex-auto [&>[data-slot=field-label]]:pt-0.5",
    },
    /**
     * Ширина поля — по длине значения, а не по ширине диалога.
     *
     * Диалог редактирования шире формы: в него помещаются список участников
     * группы и таблицы. Поля наследовали эту ширину целиком, и «3 попытки»,
     * «5 секунд», адрес шлюза и номер таблицы получали строку ввода в 854 px.
     * Поле почти во весь экран под ввод на несколько символов не помогает
     * вводить, а мешает читать: форма превращается в набор одинаковых полос,
     * по которым не видно, где короткое значение, а где длинное.
     *
     * `short` — для значений с ограниченной длиной: числа, порты, адреса,
     * маски, технические идентификаторы и выбор из списка. Свободный текст,
     * URL и пути остаются во всю ширину: там длина осмысленна.
     */
    width: {
      full: "",
      short: "max-w-[480px]",
    },
  },
  defaultVariants: {
    orientation: "vertical",
    width: "full",
  },
})

function Field({
  className,
  orientation = "vertical",
  width = "full",
  invalid = false,
  ...props
}: React.ComponentProps<"div"> &
  VariantProps<typeof fieldVariants> & { invalid?: boolean }) {
  return (
    <div
      className={cn(fieldVariants({ orientation, width }), className)}
      data-invalid={invalid}
      data-slot="field"
      role="group"
      {...props}
    />
  )
}

function FieldLabel({
  className,
  ...props
}: React.ComponentProps<typeof Label>) {
  return (
    <Label
      className={cn(
        "flex w-fit items-center gap-2 text-sm leading-[22px] font-normal text-foreground",
        className
      )}
      data-slot="field-label"
      {...props}
    />
  )
}

function FieldContent({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("flex flex-1 flex-col gap-1.5", className)}
      data-slot="field-content"
      {...props}
    />
  )
}

function FieldDescription({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      className={cn(
        "text-xs leading-5 text-muted-foreground",
        className
      )}
      data-slot="field-description"
      {...props}
    />
  )
}

function FieldSeparator({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn("h-px w-full bg-border", className)}
      data-slot="field-separator"
      {...props}
    />
  )
}

function FieldError({
  className,
  children,
  errors,
  ...props
}: React.ComponentProps<"div"> & {
  errors?: Array<{ message?: string } | undefined>
}) {
  const content = useMemo(() => {
    if (children) {
      return children
    }

    if (!errors?.length) {
      return null
    }

    const uniqueErrors = [
      ...new Map(errors.map((error) => [error?.message, error])).values(),
    ]

    if (uniqueErrors.length === 1) {
      return uniqueErrors[0]?.message
    }

    return (
      <ul className="ml-4 list-disc space-y-1">
        {uniqueErrors.map(
          (error, index) =>
            error?.message && <li key={index}>{error.message}</li>
        )}
      </ul>
    )
  }, [children, errors])

  if (!content) {
    return null
  }

  return (
    <div
      className={cn(
        "text-xs leading-5 font-normal text-destructive",
        className
      )}
      data-slot="field-error"
      role="alert"
      {...props}
    >
      {content}
    </div>
  )
}

function FieldTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn(
        "flex items-center gap-2 text-base font-medium md:text-sm",
        className
      )}
      data-slot="field-title"
      {...props}
    />
  )
}

function FieldHint({
  description,
  error,
}: {
  description?: ReactNode
  error?: ReactNode
}) {
  if (error) {
    return <FieldError>{error}</FieldError>
  }

  if (!description) {
    return null
  }

  return <FieldDescription>{description}</FieldDescription>
}

export {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldHint,
  FieldLabel,
  FieldSeparator,
  FieldTitle,
}
