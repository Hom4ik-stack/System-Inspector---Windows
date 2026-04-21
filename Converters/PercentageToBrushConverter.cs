using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace SecurityShield.Converters
{
    public class PercentageToBrushConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double pct)
            {
                if (pct >= 90) return new SolidColorBrush(Color.FromRgb(239, 68, 68));
                if (pct >= 75) return new SolidColorBrush(Color.FromRgb(245, 158, 11));
                return new SolidColorBrush(Color.FromRgb(16, 185, 129));
            }
            return Brushes.Gray;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}