using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace SecurityShield.Converters
{
    [ValueConversion(typeof(int), typeof(Visibility))]
    public class IndexToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int index
                && parameter is string paramStr
                && int.TryParse(paramStr, out int target))
            {
                return index == target ? Visibility.Visible : Visibility.Collapsed;
            }
            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
            => throw new NotImplementedException();
    }
}