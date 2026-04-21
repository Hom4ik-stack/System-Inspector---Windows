using System.Collections.Generic;

namespace SecurityShield.Services
{
    public static class PortDescriptionService
    {
        private static readonly Dictionary<int, (string Name, string Purpose)> Ports = new()
        {
            { 20, ("FTP-Data", "Передача файлов") },
            { 21, ("FTP", "Передача файлов") },
            { 22, ("SSH", "Безопасная оболочка") },
            { 23, ("Telnet", "Небезопасное удалённое управление") },
            { 25, ("SMTP", "Отправка почты") },
            { 53, ("DNS", "Система доменных имён") },
            { 80, ("HTTP", "Веб (незащищённый)") },
            { 110, ("POP3", "Получение почты") },
            { 123, ("NTP", "Синхронизация времени") },
            { 143, ("IMAP", "Получение почты") },
            { 443, ("HTTPS", "Веб (защищённый)") },
            { 445, ("SMB", "Общий доступ к файлам") },
            { 465, ("SMTPS", "Безопасная отправка почты") },
            { 587, ("SMTP", "Отправка почты") },
            { 993, ("IMAPS", "Безопасное получение почты") },
            { 995, ("POP3S", "Безопасное получение почты") },
            { 3306, ("MySQL", "База данных") },
            { 3389, ("RDP", "Удалённый рабочий стол") },
            { 5432, ("PostgreSQL", "База данных") },
            { 5900, ("VNC", "Удалённый рабочий стол") },
            { 8080, ("HTTP-Alt", "Альтернативный веб-сервер") }
        };

        public static (string Name, string Purpose) GetPortDescription(int port)
        {
            if (Ports.TryGetValue(port, out var desc)) return desc;
            if (port >= 49152) return ("Динамический", "Временный порт приложения");
            if (port > 1024) return ("Зарегистрированный", "Порт приложения");
            return ("Системный", "Системный порт");
        }
    }
}