import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

/**
 * LogSentry — анализатор логов веб-сервера (формат Apache/Nginx combined).
 *
 * Коммерческая ценность: мини-SIEM для малой компании — за секунды строит
 * отчёт по HTTP-кодам, топ IP-адресов, топ запрашиваемых URL, подозрительную
 * активность (много 4xx/5xx с одного IP). Заменяет ручной разбор гигабайтных
 * логов и платные сервисы на первом этапе.
 *
 * Запуск:  java LogSentry.java <путь-к-файлу-лога>
 * Пример:  java LogSentry.java access.log
 * Без аргументов — разбирает встроенный демо-лог.
 */
public class LogSentry {

    // 127.0.0.1 - - [10/Oct/2026:13:55:36 +0300] "GET /index.html HTTP/1.1" 200 1024
    private static final Pattern LINE = Pattern.compile(
            "^(\\S+) \\S+ \\S+ \\[[^]]+\\] \"(\\S+) (\\S+) [^\"]*\" (\\d{3}) \\S+.*");

    record Entry(String ip, String method, String url, int status) {}

    public static void main(String[] args) throws IOException {
        List<String> lines;
        String source;
        if (args.length > 0 && Files.exists(Paths.get(args[0]))) {
            lines = Files.readAllLines(Paths.get(args[0]));
            source = args[0];
        } else {
            lines = demoLog();
            source = "(встроенный демо-лог)";
        }

        List<Entry> entries = lines.stream()
                .map(LogSentry::parse)
                .flatMap(Optional::stream)
                .toList();

        System.out.println("=== LogSentry v1.0 — отчёт по логу " + source + " ===");
        System.out.printf("Строк в файле: %d, распознано: %d%n%n", lines.size(), entries.size());

        // --- Распределение HTTP-кодов по классам ---
        Map<String, Long> classes = entries.stream().collect(Collectors.groupingBy(
                e -> e.status() / 100 + "xx", TreeMap::new, Collectors.counting()));
        System.out.println("--- HTTP-коды ---");
        classes.forEach((k, v) -> System.out.printf("  %s: %d (%.1f%%)%n",
                k, v, 100.0 * v / entries.size()));

        // --- Топ-5 URL ---
        System.out.println("\n--- Топ-5 URL ---");
        top(entries.stream().collect(Collectors.groupingBy(Entry::url, Collectors.counting())), 5)
                .forEach((k, v) -> System.out.printf("  %6d  %s%n", v, k));

        // --- Топ-5 IP ---
        System.out.println("\n--- Топ-5 IP ---");
        top(entries.stream().collect(Collectors.groupingBy(Entry::ip, Collectors.counting())), 5)
                .forEach((k, v) -> System.out.printf("  %6d  %s%n", v, k));

        // --- Подозрительная активность: IP с долей ошибок > 50% и > 3 запросов ---
        System.out.println("\n--- Подозрительные IP (доля 4xx/5xx > 50%) ---");
        Map<String, List<Entry>> byIp = entries.stream().collect(Collectors.groupingBy(Entry::ip));
        boolean found = false;
        for (var e : byIp.entrySet()) {
            long errors = e.getValue().stream().filter(x -> x.status() >= 400).count();
            if (e.getValue().size() > 3 && errors * 2 > e.getValue().size()) {
                System.out.printf("  ⚠ %s: %d запросов, %d ошибок (%.0f%%)%n",
                        e.getKey(), e.getValue().size(), errors,
                        100.0 * errors / e.getValue().size());
                found = true;
            }
        }
        if (!found) System.out.println("  Подозрительной активности не обнаружено.");

        // --- Почасовая нагрузка ---
        System.out.println("\n--- Запросов по часам ---");
        Pattern hour = Pattern.compile(":(\\d{2}):");
        Map<String, Long> byHour = new TreeMap<>();
        for (String l : lines) {
            Matcher m = hour.matcher(l);
            if (m.find()) byHour.merge(m.group(1), 1L, Long::sum);
        }
        long max = byHour.values().stream().mapToLong(Long::longValue).max().orElse(1);
        byHour.forEach((h, c) ->
                System.out.printf("  %s:00 | %s %d%n", h, "█".repeat((int) (40L * c / max)), c));
    }

    static Optional<Entry> parse(String line) {
        Matcher m = LINE.matcher(line);
        if (!m.matches()) return Optional.empty();
        return Optional.of(new Entry(m.group(1), m.group(2), m.group(3),
                Integer.parseInt(m.group(4))));
    }

    static <K> Map<K, Long> top(Map<K, Long> map, int n) {
        return map.entrySet().stream()
                .sorted(Map.Entry.<K, Long>comparingByValue().reversed())
                .limit(n)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (a, b) -> a, LinkedHashMap::new));
    }

    static List<String> demoLog() {
        String[] rows = {
                "192.168.1.10 - - [07/Nov/2026:09:12:01 +0300] \"GET /index.html HTTP/1.1\" 200 2048",
                "192.168.1.10 - - [07/Nov/2026:09:12:03 +0300] \"GET /style.css HTTP/1.1\" 200 1024",
                "10.0.0.55 - - [07/Nov/2026:10:05:11 +0300] \"POST /api/login HTTP/1.1\" 200 512",
                "203.0.113.77 - - [07/Nov/2026:10:06:00 +0300] \"POST /api/login HTTP/1.1\" 401 128",
                "203.0.113.77 - - [07/Nov/2026:10:06:05 +0300] \"POST /api/login HTTP/1.1\" 401 128",
                "203.0.113.77 - - [07/Nov/2026:10:06:10 +0300] \"POST /api/login HTTP/1.1\" 401 128",
                "203.0.113.77 - - [07/Nov/2026:10:06:15 +0300] \"POST /api/login HTTP/1.1\" 401 128",
                "203.0.113.77 - - [07/Nov/2026:10:06:20 +0300] \"GET /admin HTTP/1.1\" 403 256",
                "192.168.1.22 - - [07/Nov/2026:11:30:45 +0300] \"GET /products HTTP/1.1\" 200 4096",
                "192.168.1.22 - - [07/Nov/2026:11:31:00 +0300] \"GET /products/42 HTTP/1.1\" 200 1536",
                "10.0.0.55 - - [07/Nov/2026:12:00:00 +0300] \"GET /api/orders HTTP/1.1\" 200 8192",
                "10.0.0.55 - - [07/Nov/2026:12:00:30 +0300] \"GET /api/orders/999 HTTP/1.1\" 404 256",
                "192.168.1.10 - - [07/Nov/2026:13:15:00 +0300] \"GET /index.html HTTP/1.1\" 200 2048",
                "172.16.0.8 - - [07/Nov/2026:14:20:00 +0300] \"GET /api/health HTTP/1.1\" 500 64",
                "172.16.0.8 - - [07/Nov/2026:14:21:00 +0300] \"GET /api/health HTTP/1.1\" 500 64",
        };
        return List.of(rows);
    }
}
