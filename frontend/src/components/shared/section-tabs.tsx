import {
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from "react"
import { ChevronDownIcon, ChevronUpIcon } from "lucide-react"

import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { getMobileTabPartition } from "@/components/shared/section-tabs-utils"
import { cn } from "@/lib/utils"

export type SectionTab<T extends string> = {
  value: T
  label: string
  count?: number
}

export function SectionTabs<T extends string>({
  ariaLabel,
  tabs,
  value,
  onValueChange,
  className,
}: {
  ariaLabel: string
  tabs: readonly SectionTab<T>[]
  value: T
  onValueChange: (value: T) => void
  className?: string
}) {
  const listRef = useRef<HTMLDivElement | null>(null)
  const indicatorRef = useRef<HTMLDivElement | null>(null)
  const buttonRefs = useRef<(HTMLButtonElement | null)[]>([])

  useLayoutEffect(() => {
    const list = listRef.current
    const indicator = indicatorRef.current
    const activeIndex = tabs.findIndex((tab) => tab.value === value)
    const activeTab = buttonRefs.current[activeIndex]

    if (!list || !indicator || !activeTab) {
      return
    }

    const updateIndicator = () => {
      indicator.style.transform = `translate3d(${activeTab.offsetLeft}px, 0, 0)`
      indicator.style.width = `${activeTab.offsetWidth}px`
    }

    updateIndicator()

    const resizeObserver = new ResizeObserver(updateIndicator)
    resizeObserver.observe(list)
    resizeObserver.observe(activeTab)
    window.addEventListener("resize", updateIndicator)

    return () => {
      resizeObserver.disconnect()
      window.removeEventListener("resize", updateIndicator)
    }
  }, [tabs, value])

  const activateTab = (nextValue: T, index: number) => {
    onValueChange(nextValue)

    const list = listRef.current
    const tab = buttonRefs.current[index]
    if (!list || !tab || list.scrollWidth <= list.clientWidth) {
      return
    }

    const targetLeft = Math.max(
      0,
      Math.min(
        tab.offsetLeft - (list.clientWidth - tab.offsetWidth) / 2,
        list.scrollWidth - list.clientWidth
      )
    )
    list.scrollTo({ behavior: "smooth", left: targetLeft })
  }

  const handleKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    index: number
  ) => {
    if (
      event.key !== "ArrowLeft" &&
      event.key !== "ArrowRight" &&
      event.key !== "Home" &&
      event.key !== "End"
    ) {
      return
    }

    event.preventDefault()
    const nextIndex =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? tabs.length - 1
          : (index + (event.key === "ArrowLeft" ? -1 : 1) + tabs.length) %
            tabs.length
    const nextTab = tabs[nextIndex]
    if (!nextTab) {
      return
    }

    activateTab(nextTab.value, nextIndex)
    buttonRefs.current[nextIndex]?.focus()
  }

  return (
    <>
      <MobileSectionTabs
        ariaLabel={ariaLabel}
        className={className}
        onValueChange={onValueChange}
        tabs={tabs}
        value={value}
      />

      <div
        aria-label={ariaLabel}
        className={cn(
          "relative hidden max-w-full min-w-0 flex-nowrap overflow-x-auto sm:flex",
          className
        )}
        ref={listRef}
        role="tablist"
      >
        {tabs.map((tab, index) => (
          <button
            aria-selected={value === tab.value}
            className={cn(
              "relative flex h-10 shrink-0 items-center border-b-2 border-border px-3 py-2 text-[14px] leading-[22px] font-normal transition-colors outline-none focus-visible:ring-2 focus-visible:ring-primary/25 focus-visible:ring-inset",
              value === tab.value
                ? "text-black dark:text-foreground"
                : "text-[#6e6e6e] hover:text-black dark:text-muted-foreground dark:hover:text-foreground"
            )}
            key={tab.value}
            onClick={() => activateTab(tab.value, index)}
            onKeyDown={(event) => handleKeyDown(event, index)}
            ref={(element) => {
              buttonRefs.current[index] = element
            }}
            role="tab"
            tabIndex={value === tab.value ? 0 : -1}
            type="button"
          >
            <span>{tab.label}</span>
            {typeof tab.count === "number" ? (
              // Ширина под счётчик занята постоянно: без неё «3» превращалось
              // в «11» — вкладка становилась шире, соседние уезжали вправо, и
              // подчёркивание догоняло их отдельной анимацией. 24px хватает на
              // три цифры, больше вкладок с таким счётчиком не бывает.
              <span className="ml-1.5 inline-block min-w-6 text-center text-xs font-normal text-muted-foreground tabular-nums">
                {tab.count}
              </span>
            ) : null}
          </button>
        ))}
        <div
          aria-hidden="true"
          className="keen-tab-indicator pointer-events-none absolute bottom-0 left-0 z-10 h-0.5 w-0 bg-primary"
          ref={indicatorRef}
        />
      </div>
    </>
  )
}

function MobileSectionTabs<T extends string>({
  ariaLabel,
  tabs,
  value,
  onValueChange,
  className,
}: {
  ariaLabel: string
  tabs: readonly SectionTab<T>[]
  value: T
  onValueChange: (value: T) => void
  className?: string
}) {
  const [overflowOpen, setOverflowOpen] = useState(false)
  const { visible, overflow } = useMemo(
    () => getMobileTabPartition(tabs, value),
    [tabs, value]
  )
  const listRef = useRef<HTMLDivElement | null>(null)
  const indicatorRef = useRef<HTMLDivElement | null>(null)
  const buttonRefs = useRef<(HTMLButtonElement | null)[]>([])

  useLayoutEffect(() => {
    const list = listRef.current
    const indicator = indicatorRef.current
    const activeIndex = visible.findIndex((tab) => tab.value === value)
    const activeTab = buttonRefs.current[activeIndex]
    if (!list || !indicator || !activeTab) {
      return
    }

    const updateIndicator = () => {
      indicator.style.transform = `translate3d(${activeTab.offsetLeft}px, 0, 0)`
      indicator.style.width = `${activeTab.offsetWidth}px`
    }

    updateIndicator()
    const resizeObserver = new ResizeObserver(updateIndicator)
    resizeObserver.observe(list)
    resizeObserver.observe(activeTab)
    return () => resizeObserver.disconnect()
  }, [value, visible])

  return (
    <div
      aria-label={ariaLabel}
      className={cn(
        "relative flex h-10 min-w-0 border-b-2 border-border sm:hidden",
        className
      )}
      ref={listRef}
      role="tablist"
    >
      {visible.map((tab, index) => (
        <button
          aria-selected={value === tab.value}
          className={cn(
            "min-w-0 flex-1 truncate px-2 py-2 text-[14px] leading-[22px] font-normal transition-colors outline-none focus-visible:bg-accent",
            value === tab.value
              ? "text-black dark:text-foreground"
              : "text-[#6e6e6e] dark:text-muted-foreground"
          )}
          key={tab.value}
          onClick={() => onValueChange(tab.value)}
          ref={(element) => {
            buttonRefs.current[index] = element
          }}
          role="tab"
          tabIndex={value === tab.value ? 0 : -1}
          title={tab.label}
          type="button"
        >
          {tab.label}
        </button>
      ))}

      {overflow.length > 0 ? (
        <Popover onOpenChange={setOverflowOpen} open={overflowOpen}>
          <PopoverTrigger
            render={
              <button
                aria-label={`${ariaLabel}: ${overflow.length}`}
                className="flex h-[38px] shrink-0 items-center gap-1 px-2 text-[#6e6e6e] outline-none hover:text-foreground focus-visible:bg-accent dark:text-muted-foreground"
                type="button"
              />
            }
          >
            {overflowOpen ? (
              <ChevronUpIcon className="size-5" />
            ) : (
              <ChevronDownIcon className="size-5" />
            )}
            <span aria-hidden="true" className="text-lg leading-none">
              …
            </span>
            <span className="flex size-7 items-center justify-center rounded-full bg-primary text-[14px] font-medium text-primary-foreground tabular-nums">
              {overflow.length}
            </span>
          </PopoverTrigger>
          <PopoverContent
            align="end"
            className="w-52 gap-0 rounded-[4px] p-0 shadow-lg ring-0"
            sideOffset={0}
          >
            {overflow.map((tab) => (
              <button
                className="flex h-10 w-full min-w-0 items-center justify-between gap-3 px-3 text-left text-[14px] text-[#6e6e6e] outline-none hover:bg-accent hover:text-foreground focus-visible:bg-accent dark:text-muted-foreground"
                key={tab.value}
                onClick={() => {
                  onValueChange(tab.value)
                  setOverflowOpen(false)
                }}
                role="tab"
                type="button"
              >
                <span className="truncate">{tab.label}</span>
                {typeof tab.count === "number" ? (
                  <span className="shrink-0 text-xs tabular-nums">
                    {tab.count}
                  </span>
                ) : null}
              </button>
            ))}
          </PopoverContent>
        </Popover>
      ) : null}

      <div
        aria-hidden="true"
        className="keen-tab-indicator pointer-events-none absolute bottom-[-2px] left-0 z-10 h-0.5 w-0 bg-primary"
        ref={indicatorRef}
      />
    </div>
  )
}
