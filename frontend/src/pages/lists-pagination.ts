import type { ListQueryRequest } from "@/api/generated/model/listQueryRequest"

export const LIST_PAGE_SIZE = 50

export function buildListPageRequest(
  search: string,
  offset: number,
  sort: { activeColumn: number | null; direction: "asc" | "desc" }
): ListQueryRequest {
  return {
    offset,
    limit: LIST_PAGE_SIZE,
    search: search.trim() || undefined,
    sort:
      sort.activeColumn === 0
        ? "name"
        : sort.activeColumn === 1
          ? "source"
          : "id",
    order: sort.direction,
  }
}
