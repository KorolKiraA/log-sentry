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
