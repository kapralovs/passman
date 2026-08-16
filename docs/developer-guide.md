# Руководство разработчика Passman

## Архитектура

Проект следует принципам **Clean Architecture**. Зависимости направлены внутрь — от внешних фреймворков к бизнес-логике.

```
cmd/passman/main.go          # Точка входа (фреймворки/драйверы)
       │
internal/app/                # Оркестрация (DI, запуск)
       │
internal/controllers/        # Адаптеры (CLI → use cases)
       │
internal/usecase/            # Слой бизнес-логики (интерфейсы + кейсы)
       │
internal/repository/         # Реализация хранения (файлы)
internal/crypto/             # Реализация шифрования
       │
internal/entities/           # Чистые сущности (без зависимостей)
```

### Правила слоёв
- **Внешние слои зависят от внутренних** через интерфейсы.
- **Бизнес-логика не знает** о CLI, файлах или криптографии — только об интерфейсах.
- **Нет глобального состояния**: DI через конструкторы.

## Структура пакетов

| Пакет | Назначение |
|-------|-----------|
| `cmd/passman` | Точка входа: инициализация DI, запуск |
| `internal/entities` | Чистые структуры данных (`Config`, `UserData`, `PasswordEntry`) |
| `internal/session` | Сущность сессии (`Session`) и её сериализация |
| `internal/app` | Оркестрация: `App` с полями-зависимостями, метод `Run()` |
| `internal/controllers` | Обработка CLI-аргументов, вызовы use cases |
| `internal/usecase` | Интерфейсы (`CryptoUsecase`) и бизнес-кейсы |
| `internal/repository` | Интерфейсы (`VaultRepository`, `SessionRepository`) и файловые реализации |
| `internal/crypto` | Реализация AES-256-CBC шифрования/дешифрования |

## Сборка и запуск

### Основные команды
```bash
make build    # Собрать бинарный файл
make test     # Запустить все тесты
make vet      # Статический анализ
make clean    # Удалить скомпилированные файлы
make run ARGS="..."  # Собрать и запустить с аргументами
```

### Ручная сборка
```bash
go build -o passman ./cmd/passman
```

## Тестирование

### Запуск тестов
```bash
go test ./... -v
```

### Написание тестов
- Размещайте тесты в файлах `*_test.go` рядом с тестируемым кодом.
- Используйте таблицу тестов (table-driven tests) для покрытия граничных случаев.
- Примеры: `internal/crypto/aes_test.go`, `internal/usecase/usecase_test.go`.

## Добавление новой команды

### Шаг 1: Use Case
Создайте `internal/usecase/new_feature.go`:
```go
type NewFeatureUsecase struct {
    VaultRepo  repository.VaultRepository
    Crypto     CryptoUsecase
    SessionTTL time.Duration
}

func (u *NewFeatureUsecase) Execute(sess *session.Session, args...) (*entities.UserData, error) {
    // 1. Прочитать данные
    // 2. Проверить TTL сессии
    // 3. Выполнить бизнес-логику
    // 4. Вернуть обновлённые данные или ошибку
}
```

### Шаг 2: Контроллер
Обновите `internal/controllers/controller.go`:
1. Добавьте use case в `UseCases` struct.
2. Добавьте case в `Execute` switch.
3. Реализуйте `handleNewFeature` метод.

### Шаг 3: DI
Обновите `internal/app/app.go`:
```go
newUC := usecase.NewNewFeatureUsecase(vaultRepo, cryptoSvc, sessionTTL)
useCases := controllers.UseCases{
    // ...
    New: newUC,
}
controller := controllers.NewController(configPath, sessionRepo, useCases)
```

### Шаг 4: Тесты и проверка
```bash
make test
make vet
```

## Стиль кодирования
- **Именование**: camelCase для внутренних, PascalCase для экспортируемых.
- **Интерфейсы**: Определяйте в пакете-потребителе (Near Client Pattern).
- **Обработка ошибок**: Возвращайте `error`, не паникуйте.
- **Комментарии**: Редко, фокус на "почему", а не "что".

## Безопасность
- **Шифрование**: AES-256-CBC с PKCS7, случайный IV для каждой записи.
- **Хеширование**: SHA-256 для мастер-пароля (TODO: bcrypt/scrypt).
- **Файлы**: Права `0600` для sensitive данных.
- **Никогда не логируйте** пароли или ключи.

## Известные ограничения
1. **SHA-256 без соли** уязвим к rainbow-table атакам. Рекомендуется миграция на `bcrypt`.
2. **Нет облачной синхронизации** — данные хранятся локально.
3. **Нет восстановления** мастер-пароля.
