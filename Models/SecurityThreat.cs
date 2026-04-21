namespace SecurityShield.Models
{
    public class SecurityThreat
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Severity { get; set; } = "Низкая";
        public string Description { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
    }
}