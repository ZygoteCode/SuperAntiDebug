using System.Windows.Forms;

namespace SuperAntiDebug
{
    public partial class Form1: Form
    {
        public Form1()
        {
            InitializeComponent();
            SuperAntiDebugCore.HideCurrentThreadFromDebugger();
            timer1.Start();
        }

        private void timer1_Tick(object sender, System.EventArgs e)
        {
            label1.Text = SuperAntiDebugCore.RunChecks() ? "DEBUGGER IS DETECTED" : "DEBUGGER NOT DETECTED";
        }
    }
}
