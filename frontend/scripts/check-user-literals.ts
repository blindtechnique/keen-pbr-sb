/**
 * Roadmap: «P1. Убрать пользовательские литералы из frontend вне i18n. …
 * расширить CI проверкой литералов с узким allowlist. Не запрещать кириллицу
 * вслепую: законны название языка «Русский», таблица транслитерации,
 * комментарии и тестовые данные. Проверять именно отображаемый пользователю
 * текст, включая английские literals, а не только парность существующих
 * ключей.»
 *
 * Зачем это отдельно от `check-i18n`. Тот сверяет наборы ключей и существование
 * ключей, переданных в `t()`. Литерал, который до `t()` не доехал, в его поле
 * зрения не попадает по построению — и один такой дефект уже прошёл: имена
 * внутренних VPN-серверов были зашиты по-русски, а `i18n:check` оставался
 * зелёным.
 *
 * Что считается отображаемым текстом:
 *   1. текстовый узел JSX, в котором есть буквы;
 *   2. строковое выражение в prop/property из `USER_FACING_PROPS`;
 *   3. первый аргумент toast/setError и Error, который нередко доходит до UI.
 *
 * Проверка разбирает TypeScript в AST, а не грепает: только так `className`
 * отличается от `title`, а строка внутри `t("…")` — от строки рядом с ним.
 */
import { readdirSync, readFileSync, statSync } from "node:fs"
import { dirname, relative, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import ts from "typescript"

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const frontendRoot = resolve(scriptDirectory, "..")
const sourceRoot = resolve(frontendRoot, "src")
const allowlistPath = resolve(scriptDirectory, "user-literals-allowlist.ts")

/** Пропсы, значение которых пользователь видит или слышит. */
const USER_FACING_PROPS = new Set([
  "alt",
  "aria-label",
  "aria-description",
  "aria-placeholder",
  "aria-roledescription",
  "aria-valuetext",
  "description",
  "emptyText",
  "helperText",
  "label",
  "placeholder",
  "title",
])

const USER_FACING_CALLS = new Set(["toast", "setError"])

/** Файлы, где литералы — это и есть данные, а не интерфейс. */
const SKIPPED_PATH_PARTS = ["/i18n/", "/api/generated/"]

const { allowedLiterals, untranslatedDebt } = (await import(allowlistPath)) as {
  allowedLiterals: readonly string[]
  untranslatedDebt: readonly string[]
}
const allowed = new Set([...allowedLiterals, ...untranslatedDebt])
/** Что из списков реально встретилось: долг обязан только уменьшаться. */
const seen = new Set<string>()

type Finding = { file: string; line: number; text: string; where: string }
const findings: Finding[] = []

function hasLetters(value: string): boolean {
  return /\p{L}/u.test(value)
}

/**
 * JSX-текст хранит сущности как есть (`&quot;`), а пользователь видит символ.
 * Сравнивать надо с тем, что он видит, иначе команда оболочки в списке
 * исключений никогда не совпадёт с самой собой.
 */
function decodeEntities(value: string): string {
  return value
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&nbsp;", "\u00a0")
    .replaceAll("&amp;", "&")
}

/**
 * Технические строки, которые формально содержат буквы, но пользователю не
 * показываются: идентификаторы, css-значения, форматы дат, коды.
 */
function looksTechnical(value: string): boolean {
  const trimmed = value.trim()
  if (trimmed.length < 2) return true
  if (!hasLetters(trimmed)) return true
  // kebab / snake_case / dot.path — это ключи и id. Одиночное английское
  // слово не считаем техническим: `Close` и `close` одинаково требуют i18n.
  if (/^[a-z0-9]+([-_.:/][a-z0-9]+)+$/.test(trimmed)) return true
  // Единицы, размеры, css.
  if (/^[\d\s.,]+(px|rem|em|%|s|ms|fr)$/.test(trimmed)) return true
  return false
}

function collect(file: string): void {
  const relativePath = relative(frontendRoot, file).replaceAll("\\", "/")
  const source = ts.createSourceFile(
    file,
    readFileSync(file, "utf8"),
    ts.ScriptTarget.Latest,
    true,
    file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  )

  const report = (node: ts.Node, text: string, where: string) => {
    const value = decodeEntities(text).replace(/\s+/g, " ").trim()
    if (!value || looksTechnical(value)) return
    if (allowed.has(value)) {
      seen.add(value)
      return
    }
    const { line } = source.getLineAndCharacterOfPosition(node.getStart(source))
    findings.push({ file: relativePath, line: line + 1, text: value, where })
  }

  const reportExpression = (expression: ts.Expression, where: string): void => {
    if (ts.isStringLiteralLike(expression)) {
      report(expression, expression.text, where)
      return
    }
    if (ts.isTemplateExpression(expression)) {
      const text = [
        expression.head.text,
        ...expression.templateSpans.map((span) => span.literal.text),
      ].join("${…}")
      report(expression, text, where)
      return
    }
    if (ts.isConditionalExpression(expression)) {
      reportExpression(expression.whenTrue, where)
      reportExpression(expression.whenFalse, where)
    }
  }

  const propertyName = (name: ts.PropertyName): string | undefined => {
    if (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) return name.text
    return undefined
  }

  const callName = (expression: ts.LeftHandSideExpression) => {
    if (ts.isIdentifier(expression)) return expression.text
    if (
      ts.isPropertyAccessExpression(expression) &&
      ts.isIdentifier(expression.expression)
    ) {
      return expression.expression.text
    }
    return undefined
  }

  const visit = (node: ts.Node): void => {
    if (ts.isJsxText(node)) {
      report(node, node.text, "JSX text")
    } else if (ts.isJsxAttribute(node) && ts.isIdentifier(node.name)) {
      const name = node.name.text
      const initializer = node.initializer
      if (USER_FACING_PROPS.has(name) && initializer) {
        if (ts.isStringLiteral(initializer)) {
          report(initializer, initializer.text, `prop ${name}`)
        } else if (ts.isJsxExpression(initializer) && initializer.expression) {
          reportExpression(initializer.expression, `prop ${name}`)
        }
      }
    } else if (ts.isPropertyAssignment(node)) {
      const name = propertyName(node.name)
      if (name && USER_FACING_PROPS.has(name)) {
        reportExpression(node.initializer, `property ${name}`)
      }
    } else if (ts.isCallExpression(node)) {
      const name = callName(node.expression)
      const first = node.arguments[0]
      if (name && USER_FACING_CALLS.has(name) && first) {
        reportExpression(first, `call ${name}`)
      }
    } else if (ts.isNewExpression(node)) {
      const first = node.arguments?.[0]
      if (
        ts.isIdentifier(node.expression) &&
        node.expression.text === "Error" &&
        first
      ) {
        reportExpression(first, "Error message")
      }
    }
    ts.forEachChild(node, visit)
  }

  visit(source)
}

function walk(directory: string): void {
  for (const entry of readdirSync(directory)) {
    const full = resolve(directory, entry)
    const normalized = full.replaceAll("\\", "/")
    if (SKIPPED_PATH_PARTS.some((part) => normalized.includes(part))) continue
    if (statSync(full).isDirectory()) {
      walk(full)
    } else if (full.endsWith(".tsx") || full.endsWith(".ts")) {
      collect(full)
    }
  }
}

walk(sourceRoot)

const translated = untranslatedDebt.filter((entry) => !seen.has(entry))
if (translated.length > 0) {
  console.error(
    `Эти строки уже не встречаются в коде — уберите их из untranslatedDebt:\n`
  )
  for (const entry of translated) console.error(`  ${JSON.stringify(entry)}`)
  console.error(
    "\nСписок долга может только уменьшаться; устаревшая запись прячет новую."
  )
  process.exit(1)
}

if (findings.length > 0) {
  console.error(
    `Найдено ${findings.length} пользовательских литерала(ов) вне i18n:\n`
  )
  for (const finding of findings) {
    console.error(`  ${finding.file}:${finding.line} (${finding.where})`)
    console.error(`    ${JSON.stringify(finding.text)}`)
  }
  console.error(
    "\nПеренесите текст в src/i18n/ru.ts и src/i18n/en.ts и выводите его через" +
      "\n`t()`. Если строка пользователю не показывается или это название языка," +
      "\nдобавьте её в scripts/user-literals-allowlist.ts с причиной."
  )
  process.exit(1)
}

console.log(
  "user literals check passed: " +
    `${allowedLiterals.length} allowed, ${untranslatedDebt.length} still to translate`
)
