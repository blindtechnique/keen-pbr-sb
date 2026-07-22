import { BackupPanel, RestorePanel } from "@/components/settings/backup-dialogs"
import { PageHeader } from "@/components/shared/page-header"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

export function BackupPage() {
  return (
    <>
      <PageHeader
        description="Выберите данные и скачайте единый файл конфигурации keen-pbr-sb."
        title="Резервная копия"
      />
      <Card className="max-w-3xl">
        <CardHeader>
          <CardTitle>Состав копии</CardTitle>
          <CardDescription>
            Выберите разделы, которые нужно сохранить.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <BackupPanel />
        </CardContent>
      </Card>
    </>
  )
}

export function RestorePage() {
  return (
    <>
      <PageHeader
        description="Восстановите выбранные группы из файла или откатите последнее изменение."
        title="Восстановление"
      />
      <Card className="max-w-3xl">
        <CardHeader>
          <CardTitle>Источник восстановления</CardTitle>
          <CardDescription>
            Выберите сохранённую копию или последнее автоматически сохранённое
            состояние.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <RestorePanel />
        </CardContent>
      </Card>
    </>
  )
}
