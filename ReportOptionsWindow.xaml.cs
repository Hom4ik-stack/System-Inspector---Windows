using SecurityShield.Models;
using System.Windows;
using System.Windows.Controls;

namespace SecurityShield
{
    public partial class ReportOptionsWindow : Window
    {
        public ReportOptions Options { get; private set; }

        public ReportOptionsWindow(bool isNetworkReport)
        {
            InitializeComponent();
            Options = new ReportOptions();
            DataContext = Options;

            if (isNetworkReport)
            {
                SystemPanel.Visibility = Visibility.Collapsed;
            }
            else
            {
                NetworkPanel.Visibility = Visibility.Collapsed;
            }
        }

        private void OnGenerate(object sender, RoutedEventArgs e)
        {
            DialogResult = true;
            Close();
        }

        private void OnCancel(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }

        private void OnSelectAll(object sender, RoutedEventArgs e)
        {
            SetAllCheckboxes(true);
        }

        private void OnDeselectAll(object sender, RoutedEventArgs e)
        {
            SetAllCheckboxes(false);
        }

        private void SetAllCheckboxes(bool value)
        {
            var panel = SystemPanel.Visibility == Visibility.Visible
                ? SystemPanel
                : NetworkPanel;

            foreach (var child in panel.Children)
            {
                if (child is CheckBox cb)
                    cb.IsChecked = value;
            }
        }
    }
}