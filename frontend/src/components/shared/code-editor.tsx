import { useLayoutEffect, useRef, type ReactNode } from "react"

import { cn } from "@/lib/utils"

export type CodeSyntax = "nfqws" | "list" | "log"

/**
 * A textarea with syntax colouring: the highlighted copy sits underneath and
 * the real input on top is transparent, so selection, undo and IME keep working
 * exactly as in a plain field. No editor dependency is pulled in for this.
 */
export function CodeEditor({
  value,
  onChange,
  syntax,
  className,
  readOnly = false,
  spellCheck = false,
  ...rest
}: {
  value: string
  onChange?: (value: string) => void
  syntax: CodeSyntax
  className?: string
  readOnly?: boolean
  spellCheck?: boolean
} & Omit<
  React.ComponentProps<"textarea">,
  "value" | "onChange" | "className" | "readOnly"
>) {
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const highlightRef = useRef<HTMLPreElement>(null)

  // The two layers must scroll together or the colours drift away from the text.
  useLayoutEffect(() => {
    const textarea = textareaRef.current
    const highlight = highlightRef.current
    if (!textarea || !highlight) return

    const sync = () => {
      highlight.scrollTop = textarea.scrollTop
      highlight.scrollLeft = textarea.scrollLeft
    }
    sync()
    textarea.addEventListener("scroll", sync)
    return () => textarea.removeEventListener("scroll", sync)
  }, [])

  const shared =
    "m-0 w-full whitespace-pre-wrap break-words font-mono text-xs leading-5"

  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-lg border bg-input/30 focus-within:border-ring focus-within:ring-[3px] focus-within:ring-ring/50",
        className
      )}
    >
      <pre
        aria-hidden="true"
        className={cn(shared, "pointer-events-none overflow-auto px-3 py-2")}
        ref={highlightRef}
      >
        {highlight(value, syntax)}
        {/* Trailing newline keeps the last line visible while typing. */}
        {"\n"}
      </pre>
      <textarea
        className={cn(
          shared,
          "absolute inset-0 resize-none overflow-auto bg-transparent px-3 py-2 text-transparent caret-foreground outline-none"
        )}
        onChange={(event) => onChange?.(event.target.value)}
        readOnly={readOnly}
        ref={textareaRef}
        spellCheck={spellCheck}
        value={value}
        {...rest}
      />
    </div>
  )
}

function highlight(text: string, syntax: CodeSyntax): ReactNode {
  return text.split("\n").map((line, index) => (
    <span key={index}>
      {highlightLine(line, syntax)}
      {"\n"}
    </span>
  ))
}

function highlightLine(line: string, syntax: CodeSyntax): ReactNode {
  const trimmed = line.trimStart()

  if (trimmed.startsWith("#") || trimmed.startsWith("--#")) {
    return <span className="text-muted-foreground italic">{line}</span>
  }
  if (!trimmed) {
    return line
  }

  if (syntax === "log") {
    return highlightLog(line)
  }
  if (syntax === "list") {
    return highlightListEntry(line)
  }
  return highlightNfqws(line)
}

/** KEY=value with quoted strings, --options and numbers picked out. */
function highlightNfqws(line: string): ReactNode {
  const assignment = line.match(/^(\s*)([A-Z0-9_]+)(=)(.*)$/)
  if (!assignment) {
    return highlightTokens(line)
  }

  const [, indent, key, equals, rest] = assignment
  return (
    <>
      {indent}
      <span className="text-[color:var(--color-primary)]">{key}</span>
      <span className="text-muted-foreground">{equals}</span>
      {highlightTokens(rest)}
    </>
  )
}

function highlightTokens(text: string): ReactNode {
  const pattern =
    /("[^"]*"|'[^']*'|--[a-zA-Z0-9-]+|\b\d+(?:\.\d+){3}(?:\/\d+)?\b|\b\d+\b)/g
  const parts = text.split(pattern)

  return parts.map((part, index) => {
    if (!part) return null
    if (part.startsWith('"') || part.startsWith("'")) {
      return (
        <span className="text-success" key={index}>
          {part}
        </span>
      )
    }
    if (part.startsWith("--")) {
      return (
        <span className="text-[color:var(--color-warning)]" key={index}>
          {part}
        </span>
      )
    }
    if (/^\d/.test(part)) {
      return (
        <span className="text-[color:var(--color-primary)]" key={index}>
          {part}
        </span>
      )
    }
    return <span key={index}>{part}</span>
  })
}

/** Domains, IPs and CIDR masks read differently, so colour them differently. */
function highlightListEntry(line: string): ReactNode {
  const entry = line.trim()

  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(entry)) {
    const [address, mask] = entry.split("/")
    return (
      <>
        <span className="text-[color:var(--color-primary)]">{address}</span>
        {mask ? (
          <span className="text-muted-foreground">{`/${mask}`}</span>
        ) : null}
      </>
    )
  }
  if (entry.includes(":")) {
    return <span className="text-[color:var(--color-primary)]">{line}</span>
  }
  if (entry.startsWith("http")) {
    return <span className="text-success underline">{line}</span>
  }

  const domain = entry.match(/^(.*?)(\.[a-z]{2,})$/i)
  if (domain) {
    return (
      <>
        <span>{domain[1]}</span>
        <span className="text-success">{domain[2]}</span>
      </>
    )
  }
  return line
}

/** Log levels stand out; timestamps stay quiet. */
function highlightLog(line: string): ReactNode {
  const level = line.match(/\b(ERROR|WARN(?:ING)?|INFO|DEBUG|FATAL)\b/)
  if (!level) {
    return line
  }

  const [before, after] = line.split(level[0])
  const tone =
    level[0] === "ERROR" || level[0] === "FATAL"
      ? "text-destructive"
      : level[0].startsWith("WARN")
        ? "text-[color:var(--color-warning)]"
        : "text-[color:var(--color-primary)]"

  return (
    <>
      <span className="text-muted-foreground">{before}</span>
      <span className={cn("font-semibold", tone)}>{level[0]}</span>
      <span>{after}</span>
    </>
  )
}
