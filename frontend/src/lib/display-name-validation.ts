export const DISPLAY_NAME_MAX_CODE_POINTS = 80

export type DisplayNameValidationError =
  | "invalid-unicode"
  | "control"
  | "whitespace-only"
  | "too-long"

export function countUnicodeCodePoints(value: string) {
  return Array.from(value).length
}

export function validateDisplayName(
  value: string,
  options: { allowEmpty?: boolean } = {}
): DisplayNameValidationError | undefined {
  if (!value && options.allowEmpty) {
    return undefined
  }

  let codePoints = 0
  let hasNonWhitespace = false
  for (const character of value) {
    const codePoint = character.codePointAt(0)
    if (codePoint === undefined || isSurrogate(codePoint)) {
      return "invalid-unicode"
    }
    if (isForbiddenDisplayControl(codePoint)) {
      return "control"
    }
    hasNonWhitespace ||= !isUnicodeWhitespace(codePoint)
    codePoints += 1
  }

  if (!hasNonWhitespace) {
    return "whitespace-only"
  }
  if (codePoints > DISPLAY_NAME_MAX_CODE_POINTS) {
    return "too-long"
  }
  return undefined
}

function isSurrogate(codePoint: number) {
  return codePoint >= 0xd800 && codePoint <= 0xdfff
}

function isForbiddenDisplayControl(codePoint: number) {
  return (
    codePoint < 0x20 ||
    codePoint === 0x7f ||
    (codePoint >= 0x80 && codePoint <= 0x9f) ||
    codePoint === 0x061c ||
    codePoint === 0x200e ||
    codePoint === 0x200f ||
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2066 && codePoint <= 0x2069)
  )
}

function isUnicodeWhitespace(codePoint: number) {
  return (
    (codePoint >= 0x09 && codePoint <= 0x0d) ||
    codePoint === 0x20 ||
    codePoint === 0x85 ||
    codePoint === 0xa0 ||
    codePoint === 0x1680 ||
    (codePoint >= 0x2000 && codePoint <= 0x200a) ||
    codePoint === 0x2028 ||
    codePoint === 0x2029 ||
    codePoint === 0x202f ||
    codePoint === 0x205f ||
    codePoint === 0x3000
  )
}
