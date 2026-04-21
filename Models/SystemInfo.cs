using System.Collections.Generic;

namespace SecurityShield.Models
{
    public class SystemInfo
    {
        public string OSVersion { get; set; } = "Неизвестно";
        public string Build { get; set; } = "Неизвестно";
        public string UpdateStatus { get; set; } = "Проверка...";
        public string TotalRAM { get; set; } = "Неизвестно";
        public string Processor { get; set; } = "Неизвестно";
        public string Motherboard { get; set; } = "Неизвестно";
        public string BIOS { get; set; } = "Неизвестно";
        public string ComputerName { get; set; } = "Неизвестно";
        public string Domain { get; set; } = "Неизвестно";
        public string UserName { get; set; } = "Неизвестно";
        public List<string> NetworkAdapters { get; set; } = new();
    }
}