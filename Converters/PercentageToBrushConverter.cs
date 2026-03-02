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
            if (value is double percentage)
            {
                if (percentage >= 90) return Brushes.Red;      // Более 90%
                if (percentage >= 75) return Brushes.Yellow;   // От 75% до 90%
                return Brushes.Green;                          // Менее 75%
            }
            return Brushes.Green;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}