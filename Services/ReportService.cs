using SecurityShield.Helpers;
using SecurityShield.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityShield.Services
{
    public class ReportService : IReportService
    {
        public async Task<bool> ExportReportToFileAsync(
            string filePath, ReportData data, ReportOptions options)
        {
            if (!SecurityHelper.IsValidFilePath(filePath))
                return false;
            try
            {
                var html = await Task.Run(() => BuildHtml(data, options));
                await File.WriteAllTextAsync(filePath, html, Encoding.UTF8);
                return true;
            }
            catch { return false; }
        }

        public async Task<bool> ExportNetworkReportAsync(
            string filePath, List<NetworkHost> hosts, ReportOptions options)
        {
            if (!SecurityHelper.IsValidFilePath(filePath))
                return false;
            try
            {
                var html = await Task.Run(
                    () => BuildNetworkHtml(hosts, options));
                await File.WriteAllTextAsync(filePath, html, Encoding.UTF8);
                return true;
            }
            catch { return false; }
        }

        private string BuildHtml(ReportData data, ReportOptions opt)
        {
            var sb = new StringBuilder();
            sb.AppendLine(
                "<!DOCTYPE html><html lang='ru'><head>" +
                "<meta charset='UTF-8'>");
            sb.AppendLine(
                "<title>System Inspector — Отчёт</title>");
            AppendStyles(sb);
            sb.AppendLine("<h1>Отчёт о безопасности системы</h1>");
            sb.AppendLine(
                $"<p><b>Дата:</b> {Esc(data.ReportDate)}</p>");
            sb.AppendLine(
                $"<p><b>Оценка:</b> " +
                $"{Esc(data.OverallSecurityStatus)}</p>");

            if (opt.IncludeSystemInfo && data.SystemInfo != null)
            {
                sb.AppendLine("<h2>Системная информация</h2>");
                sb.AppendLine("<table>");
                AppendRow(sb, "Компьютер",
                    data.SystemInfo.ComputerName);
                AppendRow(sb, "Пользователь",
                    data.SystemInfo.UserName);
                AppendRow(sb, "ОС",
                    data.SystemInfo.OSVersion);
                AppendRow(sb, "Сборка",
                    data.SystemInfo.Build);
                AppendRow(sb, "Процессор",
                    data.SystemInfo.Processor);
                AppendRow(sb, "ОЗУ",
                    data.SystemInfo.TotalRAM);
                AppendRow(sb, "Мат. плата",
                    data.SystemInfo.Motherboard);
                AppendRow(sb, "Обновления",
                    data.SystemInfo.UpdateStatus);
                sb.AppendLine("</table>");
            }

            if (opt.IncludeSecurityChecks
                && data.SecurityChecks?.Any() == true)
            {
                sb.AppendLine("<h2>Проверки безопасности</h2>");
                sb.AppendLine(
                    "<table><tr><th>Проверка</th><th>Категория</th>" +
                    "<th>Статус</th><th>Детали</th>" +
                    "<th>Рекомендация</th></tr>");
                foreach (var c in data.SecurityChecks)
                {
                    string cls = c.IsCritical ? "risk"
                        : c.Status.Contains("OK") ? "ok" : "warn";
                    sb.AppendLine(
                        $"<tr><td>{Esc(c.CheckName)}</td>" +
                        $"<td>{Esc(c.Category)}</td>" +
                        $"<td class='{cls}'>{Esc(c.Status)}</td>" +
                        $"<td>{Esc(c.Details)}</td>" +
                        $"<td>{Esc(c.Recommendation)}</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            if (opt.IncludeThreats && data.Threats?.Any() == true)
            {
                sb.AppendLine("<h2>Обнаруженные угрозы</h2>");
                sb.AppendLine(
                    "<table><tr><th>Угроза</th><th>Важность</th>" +
                    "<th>Описание</th><th>Рекомендация</th></tr>");
                foreach (var t in data.Threats)
                    sb.AppendLine(
                        $"<tr><td>{Esc(t.Name)}</td>" +
                        $"<td class='risk'>{Esc(t.Severity)}</td>" +
                        $"<td>{Esc(t.Description)}</td>" +
                        $"<td>{Esc(t.Recommendation)}</td></tr>");
                sb.AppendLine("</table>");
            }

            if (opt.IncludeProcesses
                && data.TopProcesses?.Any() == true)
            {
                sb.AppendLine("<h2>Процессы (топ-10 по памяти)</h2>");
                sb.AppendLine(
                    "<table><tr><th>Имя</th><th>PID</th>" +
                    "<th>ЦП %</th><th>Память МБ</th>" +
                    "<th>Путь</th></tr>");
                foreach (var p in data.TopProcesses)
                    sb.AppendLine(
                        $"<tr><td>{Esc(p.Name)}</td>" +
                        $"<td>{p.Id}</td>" +
                        $"<td>{p.Cpu:F1}</td>" +
                        $"<td>{p.MemoryMB:F0}</td>" +
                        $"<td>{Esc(p.ProcessPath)}</td></tr>");
                sb.AppendLine("</table>");
            }

            if (opt.IncludeDrives && data.Drives?.Any() == true)
            {
                sb.AppendLine("<h2>Дисковые накопители</h2>");
                sb.AppendLine(
                    "<table><tr><th>Диск</th><th>Тип</th>" +
                    "<th>Формат</th><th>Всего</th>" +
                    "<th>Свободно</th><th>Занято %</th></tr>");
                foreach (var d in data.Drives)
                    sb.AppendLine(
                        $"<tr><td>{Esc(d.Name)}</td>" +
                        $"<td>{Esc(d.DriveType)}</td>" +
                        $"<td>{Esc(d.DriveFormat)}</td>" +
                        $"<td>{d.TotalSpaceFormatted}</td>" +
                        $"<td>{d.FreeSpaceFormatted}</td>" +
                        $"<td>{d.UsedPercentage:F0}%</td></tr>");
                sb.AppendLine("</table>");
            }

            if (opt.IncludeDrivers && data.Drivers?.Any() == true)
            {
                sb.AppendLine("<h2>Драйверы</h2>");
                sb.AppendLine(
                    "<table><tr><th>Драйвер</th>" +
                    "<th>Производитель</th><th>Версия</th>" +
                    "<th>Дата</th><th>Подпись</th></tr>");
                foreach (var d in data.Drivers)
                    sb.AppendLine(
                        $"<tr><td>{Esc(d.Name)}</td>" +
                        $"<td>{Esc(d.Manufacturer)}</td>" +
                        $"<td>{Esc(d.Version)}</td>" +
                        $"<td>{Esc(d.Date)}</td>" +
                        $"<td>{Esc(d.DigitalSignature)}</td></tr>");
                sb.AppendLine("</table>");
            }

            if (opt.IncludeDevices && data.Devices?.Any() == true)
            {
                sb.AppendLine("<h2>Устройства</h2>");
                sb.AppendLine(
                    "<table><tr><th>Имя</th><th>Категория</th>" +
                    "<th>Производитель</th><th>Тип</th>" +
                    "<th>Статус</th></tr>");
                foreach (var d in data.Devices)
                    sb.AppendLine(
                        $"<tr><td>{Esc(d.Name)}</td>" +
                        $"<td>{Esc(d.Category)}</td>" +
                        $"<td>{Esc(d.Manufacturer)}</td>" +
                        $"<td>{Esc(d.Type)}</td>" +
                        $"<td>{Esc(d.Status)}</td></tr>");
                sb.AppendLine("</table>");
            }

            if (opt.IncludeNetworkHosts
                && data.NetworkHosts?.Any(h => h.IsOnline) == true)
                AppendNetworkSection(sb, data.NetworkHosts);

            sb.AppendLine("</div></body></html>");
            return sb.ToString();
        }

        private string BuildNetworkHtml(
            List<NetworkHost> hosts, ReportOptions opt)
        {
            var sb = new StringBuilder();
            sb.AppendLine(
                "<!DOCTYPE html><html lang='ru'><head>" +
                "<meta charset='UTF-8'>");
            sb.AppendLine(
                "<title>System Inspector — Сетевой отчёт</title>");
            AppendStyles(sb);
            sb.AppendLine(
                "<h1>Отчёт сетевого аудита безопасности</h1>");
            sb.AppendLine(
                $"<p><b>Дата:</b> " +
                $"{DateTime.Now:dd.MM.yyyy HH:mm}</p>");

            if (opt.IncludeStatistics)
            {
                int online = hosts.Count(h => h.IsOnline);
                int audited = hosts.Count(h => h.SecurityScore >= 0);
                int safe = hosts.Count(h => h.SecurityScore >= 80);
                int vulnerable = hosts.Count(
                    h => h.SecurityScore >= 0
                         && h.SecurityScore < 70);

                sb.AppendLine("<div class='stats'>");
                sb.AppendLine(
                    $"<div class='stat'>" +
                    $"<span class='sn'>Онлайн</span>" +
                    $"<span class='sv'>{online}</span></div>");
                sb.AppendLine(
                    $"<div class='stat'>" +
                    $"<span class='sn'>Проверено</span>" +
                    $"<span class='sv'>{audited}</span></div>");
                sb.AppendLine(
                    $"<div class='stat'>" +
                    $"<span class='sn ok'>Защищены</span>" +
                    $"<span class='sv ok'>{safe}</span></div>");
                sb.AppendLine(
                    $"<div class='stat'>" +
                    $"<span class='sn risk'>С проблемами</span>" +
                    $"<span class='sv risk'>{vulnerable}</span></div>");
                sb.AppendLine("</div>");
            }

            if (opt.IncludeHostDetails)
                AppendNetworkSection(sb, hosts);

            if (opt.IncludeHostChecks)
            {
                foreach (var h in hosts.Where(
                    h => h.ScanResult?.SecurityChecks?.Any() == true))
                {
                    sb.AppendLine(
                        $"<h3>{Esc(h.IpAddress)} — " +
                        $"{Esc(h.HostName)}</h3>");
                    sb.AppendLine(
                        "<table><tr><th>Проверка</th>" +
                        "<th>Категория</th><th>Статус</th>" +
                        "<th>Детали</th>" +
                        "<th>Рекомендация</th></tr>");
                    foreach (var c in h.ScanResult!.SecurityChecks)
                    {
                        string cls = c.IsCritical ? "risk"
                            : c.Status.Contains("OK") ? "ok" : "warn";
                        sb.AppendLine(
                            $"<tr><td>{Esc(c.CheckName)}</td>" +
                            $"<td>{Esc(c.Category)}</td>" +
                            $"<td class='{cls}'>" +
                            $"{Esc(c.Status)}</td>" +
                            $"<td>{Esc(c.Details)}</td>" +
                            $"<td>{Esc(c.Recommendation)}" +
                            $"</td></tr>");
                    }
                    sb.AppendLine("</table>");
                }
            }

            sb.AppendLine("</div></body></html>");
            return sb.ToString();
        }

        private void AppendNetworkSection(
            StringBuilder sb, List<NetworkHost> hosts)
        {
            sb.AppendLine("<h2>Хосты</h2>");
            sb.AppendLine(
                "<table><tr><th>IP</th><th>Имя</th>" +
                "<th>Статус</th><th>ОС</th>" +
                "<th>Оценка</th><th>Детали</th></tr>");
            foreach (var h in hosts.Where(h => h.IsOnline))
            {
                string cls = h.SecurityScore >= 80 ? "ok"
                    : h.SecurityScore >= 50 ? "warn"
                    : h.SecurityScore >= 0 ? "risk" : "";
                string score = h.SecurityScore >= 0
                    ? $"{h.SecurityScore}/100" : "—";
                sb.AppendLine(
                    $"<tr><td>{Esc(h.IpAddress)}</td>" +
                    $"<td>{Esc(h.HostName)}</td>" +
                    $"<td>{Esc(h.Status)}</td>" +
                    $"<td>{Esc(h.OsVersion)}</td>" +
                    $"<td class='{cls}'>{score}</td>" +
                    $"<td>{Esc(h.ScanDetails)}</td></tr>");
            }
            sb.AppendLine("</table>");
        }

        private void AppendRow(
            StringBuilder sb, string label, string value)
        {
            sb.AppendLine(
                $"<tr><td><b>{Esc(label)}</b></td>" +
                $"<td>{Esc(value)}</td></tr>");
        }

        private void AppendStyles(StringBuilder sb)
        {
            sb.AppendLine("<style>");
            sb.AppendLine(
                "body{font-family:'Segoe UI',sans-serif;" +
                "background:#f1f5f9;color:#1e293b;" +
                "margin:0;padding:20px}");
            sb.AppendLine(
                ".c{max-width:1100px;margin:0 auto;" +
                "background:#fff;padding:32px;" +
                "border-radius:8px;" +
                "box-shadow:0 1px 3px rgba(0,0,0,.1)}");
            sb.AppendLine(
                "h1{color:#0f172a;" +
                "border-bottom:2px solid #3b82f6;" +
                "padding-bottom:8px}");
            sb.AppendLine(
                "h2{color:#334155;margin-top:28px} " +
                "h3{color:#475569;margin-top:20px}");
            sb.AppendLine(
                "table{width:100%;border-collapse:collapse;" +
                "margin-top:8px}");
            sb.AppendLine(
                "th,td{border:1px solid #e2e8f0;padding:10px;" +
                "text-align:left;font-size:13px}");
            sb.AppendLine(
                "th{background:#f8fafc;" +
                "font-weight:600;color:#475569}");
            sb.AppendLine(
                ".ok{color:#10b981;font-weight:600}" +
                ".risk{color:#ef4444;font-weight:600}" +
                ".warn{color:#f59e0b;font-weight:600}");
            sb.AppendLine(
                ".stats{display:flex;gap:16px;margin:16px 0}");
            sb.AppendLine(
                ".stat{background:#f8fafc;" +
                "border:1px solid #e2e8f0;border-radius:8px;" +
                "padding:16px 24px;text-align:center}");
            sb.AppendLine(
                ".sn{display:block;font-size:12px;" +
                "color:#64748b}" +
                ".sv{display:block;font-size:28px;" +
                "font-weight:700;margin-top:4px}");
            sb.AppendLine("</style></head><body><div class='c'>");
        }

        private static string Esc(string? s) =>
            System.Net.WebUtility.HtmlEncode(s ?? "")
            ?? string.Empty;
    }
}