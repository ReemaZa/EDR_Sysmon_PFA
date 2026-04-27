"""Sysmon event subscription using win32evtlog (EvtSubscribe API).

Responsibility: Listen to Windows Sysmon events and deliver them to callbacks.
Uses bookmarks to persist progress and resume from where it stopped.

Parsing and normalization is handled by ingestion module.
"""
import traceback
import sys
import threading
import time
import win32evtlog
import pywintypes
from typing import Callable
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.core.ingestion import parse_sysmon_event


# Bookmark file to persist progress
BOOKMARK_FILE = "sysmon_bookmark.xml"


def load_bookmark_xml() -> str | None:
    """Load persisted bookmark XML from disk. Returns None if not found."""
    try:
        with open(BOOKMARK_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return content if content else None
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[ERROR] Error loading bookmark file: {e}")
        return None


def save_bookmark_xml(bookmark_handle) -> None:
    """Render bookmark handle to XML and persist it to disk."""
    try:
        xml = win32evtlog.EvtRender(bookmark_handle, win32evtlog.EvtRenderBookmark)
        with open(BOOKMARK_FILE, "w", encoding="utf-8") as f:
            f.write(xml)
    except pywintypes.error as e:
        print(f"[ERROR] Error rendering bookmark: {e}")
    except Exception as e:
        print(f"[ERROR] Error saving bookmark file: {e}")


def create_bookmark(bookmark_xml: str = None):
    """
    Create a bookmark handle.
    - Pass bookmark_xml to resume from last position.
    - Pass None to create a fresh bookmark.
    """
    try:
        handle = win32evtlog.EvtCreateBookmark(bookmark_xml)
        if not handle:
            raise Exception("EvtCreateBookmark returned None")
        return handle
    except pywintypes.error as e:
        print(f"[ERROR] Error creating bookmark: {e}")
        return None


def update_bookmark(bookmark_handle, event_handle) -> None:
    """Reposition the bookmark to point to a specific event."""
    try:
        win32evtlog.EvtUpdateBookmark(bookmark_handle, event_handle)
        save_bookmark_xml(bookmark_handle) 
    except pywintypes.error as e:
        print(f"[ERROR] Error updating bookmark: {e}")


class SysmonEventWatcher(threading.Thread):
    """Subscribe to Sysmon events using EvtSubscribe (Windows Vista+).
    
    Responsibility: Listen to Windows events and deliver parsed events to callback.
    Uses bookmarks to persist progress and resume from where it stopped.
    
    Callback signature: def callback(event: dict) -> None
    where event is a normalized dict from ingestion.parse_sysmon_event()
    """

    def __init__(self, callback: Callable, stop_event=None):
        super().__init__(daemon=True)
        self.callback = callback
        self._stop_event = stop_event if stop_event is not None else threading.Event()
        self.h_subscription = None
        self.bookmark_handle = None

    def stop(self):
        """Signal the watcher to stop."""
        self._stop_event.set()

    def _event_callback(self, action, context, event_handle):
        """Internal callback function called by Windows when new events arrive."""
        try:
            # Only process delivery actions
            if action != win32evtlog.EvtSubscribeActionDeliver:
                return
            
            # Render event as XML
            xml_content = win32evtlog.EvtRender(
                event_handle,
                win32evtlog.EvtRenderEventXml
            )
            
            # Parse and normalize using ingestion module
            evt = parse_sysmon_event(xml_content)
            #print('**********************************')
            #from pprint import pprint

            #pprint(evt)
            #print('**********************************')

            if evt is None:
                print(f"[WARNING] Failed to parse event")
                return
            
            # Update bookmark to this event (in memory)
            if self.bookmark_handle is not None:
                update_bookmark(self.bookmark_handle, event_handle)
            
            # Deliver to callback
            try:
                self.callback(evt)
            except Exception as e:
                print(traceback.print_exception(e))
        
        except Exception as e:
            print(f"[ERROR] Failed to process event: {e}")

    def run(self):
        """Start listening to Sysmon events."""
        try:
            # Subscribe to Sysmon events
            channel_name = "Microsoft-Windows-Sysmon/Operational"
            
            # Load previously saved bookmark (if exists)
            saved_bookmark_xml = load_bookmark_xml()
            
            # Determine subscription flags based on whether we have a saved bookmark
            if saved_bookmark_xml:
                print("[INFO] Resuming from saved bookmark position")
                self.bookmark_handle = create_bookmark(saved_bookmark_xml)
                if self.bookmark_handle is None:
                    print("[WARNING] Failed to restore bookmark. Starting from oldest record.")
                    self.bookmark_handle = create_bookmark(None)
                    flags = win32evtlog.EvtSubscribeStartAtOldestRecord
                else:
                    flags = win32evtlog.EvtSubscribeStartAfterBookmark
            else:
                print("[INFO] No saved bookmark found. Starting from future events")
                self.bookmark_handle = create_bookmark(None)
                flags = win32evtlog.EvtSubscribeToFutureEvents
            
            if self.bookmark_handle is None:
                raise Exception("Failed to create bookmark handle")
            
            # Create subscription
            self.h_subscription = win32evtlog.EvtSubscribe(
                channel_name,
                flags,
                None,
                Callback=self._event_callback,
                Bookmark=self.bookmark_handle if flags == win32evtlog.EvtSubscribeStartAfterBookmark else None
            )
            self._stop_event.wait()
            print("[INFO] Sysmon event watcher initialized with EvtSubscribe")
           # while not self._stop_event.is_set():
             #   time.sleep(1)
           
                    
        except pywintypes.error as e:
            print(f"[ERROR] Failed to initialize event subscription: {e}")
        finally:
            # Always save bookmark on exit
            try:
                if self.bookmark_handle is not None:
                    save_bookmark_xml(self.bookmark_handle)
                    print("[INFO] Bookmark saved. Will resume from here on next start.")
            except Exception as e:
                print(f"[ERROR] Failed to save bookmark on exit: {e}")
            
            try:
                if self.h_subscription is not None:
                    print('Closing event subscription handle')
                    win32evtlog.CloseEventLog(self.h_subscription)
            except Exception as e:
                print(f"[WARNING] Error closing subscription handle: {e}")
