from ui import CyberToolkit
from splash_screen import SplashScreen
import customtkinter as ctk

def show_splash_and_app():
    # Create and setup main app
    app = CyberToolkit()
    app.withdraw()  # Hide initially
    
    # Create splash screen
    splash = SplashScreen(app)
    
    def on_splash_complete():
        """Callback when splash screen is done"""
        try:
            app.deiconify()  # Show main window
            app.lift()  # Bring to front
            app.focus_force()  # Force focus
            app.center_window()  # Center on screen
            
            # Start with port scanner view
            app.show_port_scanner()
            
        except Exception as e:
            print(f"Error showing main window: {str(e)}")
    
    # Set callback for splash screen completion
    splash.set_completion_callback(on_splash_complete)
    
    # Start the app
    app.mainloop()

def main():
    try:
        show_splash_and_app()
    except Exception as e:
        print(f"Application error: {str(e)}")

if __name__ == "__main__":
    main()
