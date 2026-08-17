import { readdirSync, readFileSync, statSync } from "node:fs"
import { dirname, relative, resolve, sep } from "node:path"
import { fileURLToPath } from "node:url"
import ts from "typescript"

import { enTranslation } from "../src/i18n/en"
import { ruTranslation } from "../src/i18n/ru"
import { dynamicTranslationUsages } from "./i18n-dynamic-keys"

type TranslationTree = Readonly<Record<string, unknown>>

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const frontendRoot = resolve(scriptDirectory, "..")
const sourceRoot = resolve(frontendRoot, "src")
const errors: string[] = []

const enKeys = flattenTranslationKeys(enTranslation)
const ruKeys = flattenTranslationKeys(ruTranslation)

reportSetDifference("missing from ru", enKeys, ruKeys)
reportSetDifference("missing from en", ruKeys, enKeys)

const declaredUsageHits = new Set<number>()
let staticUsageCount = 0
let dynamicUsageCount = 0

for (const file of walkSourceFiles(sourceRoot)) {
  const sourceText = readFileSync(file, "utf8")
  const sourceFile = ts.createSourceFile(
    file,
    sourceText,
    ts.ScriptTarget.Latest,
    true,
    file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS
  )
  const relativeFile = normalizePath(relative(frontendRoot, file))

  visit(sourceFile, (call) => {
    if (!isTranslationCall(call) || call.arguments.length === 0) return
    const argument = call.arguments[0]
    const staticKeys = extractStaticKeys(argument)
    if (staticKeys) {
      staticUsageCount += 1
      for (const key of staticKeys) {
        if (!enKeys.has(key)) {
          errors.push(
            `${locationOf(sourceFile, argument)}: translation key '${key}' does not exist`
          )
        }
      }
      return
    }

    dynamicUsageCount += 1
    const expression = normalizeExpression(argument.getText(sourceFile))
    const declarationIndex = dynamicTranslationUsages.findIndex(
      (usage) =>
        usage.file === relativeFile && globMatches(usage.argument, expression, true)
    )
    if (declarationIndex === -1) {
      errors.push(
        `${locationOf(sourceFile, argument)}: dynamic translation expression '${expression}' is not declared in scripts/i18n-dynamic-keys.ts`
      )
      return
    }
    declaredUsageHits.add(declarationIndex)
  })
}

dynamicTranslationUsages.forEach((usage, index) => {
  if (!declaredUsageHits.has(index)) {
    errors.push(
      `scripts/i18n-dynamic-keys.ts: unused declaration for ${usage.file}: ${usage.argument}`
    )
  }
  for (const keyPattern of usage.keys) {
    if (![...enKeys].some((key) => globMatches(keyPattern, key, false))) {
      errors.push(
        `scripts/i18n-dynamic-keys.ts: '${keyPattern}' for ${usage.file} matches no translation key`
      )
    }
  }
})

if (errors.length > 0) {
  console.error(`i18n check failed with ${errors.length} error(s):`)
  for (const error of errors) console.error(`- ${error}`)
  process.exit(1)
}

console.log(
  `i18n check passed: ${enKeys.size} keys per locale, ${staticUsageCount} static and ${dynamicUsageCount} declared dynamic usages.`
)

function flattenTranslationKeys(tree: TranslationTree): Set<string> {
  const keys = new Set<string>()

  const walk = (value: unknown, path: string): void => {
    if (typeof value === "string") {
      keys.add(path)
      return
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      errors.push(`translation '${path}' must be a string or nested object`)
      return
    }
    for (const [name, child] of Object.entries(value)) {
      walk(child, path ? `${path}.${name}` : name)
    }
  }

  walk(tree, "")
  return keys
}

function reportSetDifference(
  description: string,
  expected: ReadonlySet<string>,
  actual: ReadonlySet<string>
): void {
  for (const key of expected) {
    if (!actual.has(key)) errors.push(`${description}: ${key}`)
  }
}

function walkSourceFiles(directory: string): string[] {
  const files: string[] = []
  for (const name of readdirSync(directory)) {
    const path = resolve(directory, name)
    const stat = statSync(path)
    if (stat.isDirectory()) {
      if (!path.endsWith(`${sep}api${sep}generated`)) {
        files.push(...walkSourceFiles(path))
      }
      continue
    }
    if (path.endsWith(".ts") || path.endsWith(".tsx")) files.push(path)
  }
  return files
}

function visit(
  node: ts.Node,
  onTranslationCall: (call: ts.CallExpression) => void
): void {
  if (ts.isCallExpression(node)) onTranslationCall(node)
  ts.forEachChild(node, (child) => visit(child, onTranslationCall))
}

function isTranslationCall(call: ts.CallExpression): boolean {
  const callee = call.expression
  return (
    (ts.isIdentifier(callee) && callee.text === "t") ||
    (ts.isPropertyAccessExpression(callee) && callee.name.text === "t")
  )
}

function extractStaticKeys(expression: ts.Expression): readonly string[] | null {
  if (
    ts.isStringLiteral(expression) ||
    ts.isNoSubstitutionTemplateLiteral(expression)
  ) {
    return [expression.text]
  }
  if (ts.isParenthesizedExpression(expression)) {
    return extractStaticKeys(expression.expression)
  }
  if (ts.isConditionalExpression(expression)) {
    const whenTrue = extractStaticKeys(expression.whenTrue)
    const whenFalse = extractStaticKeys(expression.whenFalse)
    return whenTrue && whenFalse ? [...whenTrue, ...whenFalse] : null
  }
  return null
}

function normalizeExpression(value: string): string {
  return value.replaceAll(/\s+/g, " ").trim()
}

function normalizePath(value: string): string {
  return value.replaceAll("\\", "/")
}

function globMatches(pattern: string, value: string, freeform: boolean): boolean {
  const wildcard = freeform ? ".*" : "[^.]+"
  const expression = pattern
    .split("*")
    .map(escapeRegExp)
    .join(wildcard)
  return new RegExp(`^${expression}$`).test(value)
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function locationOf(sourceFile: ts.SourceFile, node: ts.Node): string {
  const position = sourceFile.getLineAndCharacterOfPosition(node.getStart())
  return `${normalizePath(relative(frontendRoot, sourceFile.fileName))}:${position.line + 1}:${position.character + 1}`
}
