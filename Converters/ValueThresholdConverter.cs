using System;
using System.Globalization;
using System.Windows.Data;

namespace SecurityShield.Converters
{
    public class ValueThresholdConverter : IValueConverter
    {
        public double HighThreshold { get; set; } = 50;
        public double MediumThreshold { get; set; } = 20;

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            double val = value switch
            {
                double d => d,
                int i => i,
                float f => f,
                long l => l,
                _ => 0
            };
            if (val >= HighThreshold) return "High";
            if (val >= MediumThreshold) return "Medium";
            return "Normal";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}