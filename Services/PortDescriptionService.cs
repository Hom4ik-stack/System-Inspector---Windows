using System.Collections.Generic;

namespace SecurityShield.Services
{
  
    public static class PortDescriptionService
    {
        private static readonly Dictionary<int, (string Name, string Purpose)> WellKnownPorts = new Dictionary<int, (string Name, string Purpose)>
        {
            { 20, ("FTP (Data)", "Передача файлов (старый)") },
            { 21, ("FTP (Control)", "Передача файлов (старый)") },
            { 22, ("SSH", "Безопасное подключение к оболочке") },
            { 23, ("Telnet", "Небезопасное удаленное управление") },
            { 25, ("SMTP", "Отправка почты (E-mail)") },
            { 53, ("DNS", "Система доменных имен (Интернет)") },
            { 80, ("HTTP", "Веб-браузер (незащищенный)") },
            { 110, ("POP3", "Получение почты (E-mail)") },
            { 123, ("NTP", "Синхронизация времени") },
            { 143, ("IMAP", "Получение почты (E-mail)") },
            { 443, ("HTTPS", "Веб-браузер (безопасный)") },
            { 445, ("SMB", "Общий доступ к файлам (Риск!)") },
            { 465, ("SMTPS", "Отправка почты (безопасная)") },
            { 587, ("SMTP", "Отправка почты (передача)") },
            { 993, ("IMAPS", "Получение почты (безопасное)") },
            { 995, ("POP3S", "Получение почты (безопасное)") },
            { 3306, ("MySQL", "База данных") },
            { 3389, ("RDP", "Удаленный рабочий стол (Риск!)") },
            { 5060, ("SIP", "IP-телефония (VoIP)") },
            { 5061, ("SIPS", "IP-телефония (VoIP, безопасная)") },
            { 5222, ("XMPP", "Мессенджеры (Jabber)") },
            { 5223, ("XMPP", "Мессенджеры (SSL)") },
            { 5900, ("VNC", "Удаленный рабочий стол") },
            { 6667, ("IRC", "Чаты (старый)") },
            { 8080, ("HTTP-Alt", "Веб-сервер (альтернативный)") }
        };

     
        public static (string Name, string Purpose) GetPortDescription(int port)
        {
            if (WellKnownPorts.TryGetValue(port, out var description))
            {
                return description;
            }

            if (port >= 49152)
            {
                return ("Динамический", "Временный порт приложения");
            }

            if (port > 1024)
            {
                return ("Зарегистрированный", "Порт приложения или игры");
            }

            return ("Неизвестный", "Системный или неизвестный порт");
        }

    
        public static string GetLocalPortDescription(int port)
        {
            if (port < 1024) return "Системный порт";
            if (port < 49152) return "Порт приложения";
            return "Динамический (временный) порт";
        }
    }
}