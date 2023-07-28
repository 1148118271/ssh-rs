use async_std::io::{Read, Write};
use futures::channel::mpsc::{unbounded, UnboundedReceiver};
use futures::StreamExt;
use std::marker::Send;
use std::task::Waker;
use std::{cell::RefCell, rc::Rc, task::Poll};
use wasm_bindgen::{prelude::Closure, JsCast};
use web_sys::{Blob, FileReader, MessageEvent, WebSocket};

use crate::{console_log, console_log_jsvalue};
#[cfg(target_family = "wasm")]
pub struct WebSocketStream {
    ws: Rc<RefCell<WebSocket>>,
    read_receiver: UnboundedReceiver<Vec<u8>>,
    temp_read_buffer: Vec<u8>,
    // Save the waker so we can wake up the task when we receive a message
    read_waker: Rc<RefCell<Option<Waker>>>,
    write_waker: Rc<RefCell<Option<Waker>>>,
}

#[cfg(target_family = "wasm")]
impl Read for WebSocketStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let ready_state = self.ws.as_ref().borrow_mut().ready_state();
        console_log!("read message is called, readystate = {:?}", ready_state);
        let this = self.as_mut().get_mut();
        if ready_state == 0 {
            *(this.read_waker.borrow_mut()) = Some(cx.waker().clone());
            return Poll::Pending;
        }

        if ready_state == 2 || ready_state == 3 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("websocket closing or closed"),
            )));
        }

        match this.read_receiver.poll_next_unpin(cx) {
            Poll::Ready(Some(data)) => {
                this.temp_read_buffer.extend_from_slice(&data);
            }
            Poll::Ready(None) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "WebSocket closed",
                )));
            }
            Poll::Pending => {
                if this.temp_read_buffer.is_empty() {
                    console_log!("read pending");
                    return Poll::Pending;
                }
            }
        }

        if !this.temp_read_buffer.is_empty() {
            // if temp buffer still has something in it
            let len = buf.len().min(this.temp_read_buffer.len());
            // Copy from temp_read_buffer to buf
            buf[..len].copy_from_slice(&this.temp_read_buffer[..len]);

            // Remove the bytes we have just copied from temp_read_buffer
            this.temp_read_buffer.drain(..len);
            return Poll::Ready(Ok(len));
        }
        Poll::Ready(Ok(0))
    }
}

#[cfg(target_family = "wasm")]
impl Write for WebSocketStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let ready_state = self.ws.as_ref().borrow_mut().ready_state();
        console_log!("write called state = {:?}", &ready_state,);

        if ready_state == 0 {
            *(self.get_mut().write_waker.borrow_mut()) = Some(cx.waker().clone());
            return Poll::Pending;
        }

        if ready_state == 2 || ready_state == 3 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                format!("websocket closing or closed"),
            )));
        }

        if let Err(e) = self.ws.as_ref().borrow_mut().send_with_u8_array(buf) {
            console_log_jsvalue!(e);
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("websocket error"),
            )));
        }

        console_log!("write successful");
        return Poll::Ready(Ok(buf.len()));
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        return Poll::Ready(Ok(())); // we don't need to flush webscoket
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Ok(_) = self.ws.as_ref().borrow_mut().close() {
            return Poll::Ready(Ok(()));
        }
        return Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "Failed to close WebSocket",
        )));
    }
}

#[cfg(target_family = "wasm")]
impl WebSocketStream {
    pub fn new(connection_str: String) -> Result<WebSocketStream, Box<dyn std::error::Error>> {
        let ws = WebSocket::new(&connection_str.as_str()).expect("websocket creation failed");
        let ws_ref = Rc::new(RefCell::new(ws));
        let (sender, reader) = unbounded::<Vec<u8>>();

        let read_waker = Rc::new(RefCell::new(None::<Waker>));
        let read_waker_clone = read_waker.clone();
        let onmessage_callback = {
            Closure::wrap(Box::new(move |e: MessageEvent| {
                console_log!("received msg from websoket");
                let sender_copy = sender.clone();
                let waker_double_clone = read_waker_clone.clone();
                if let Ok(blob) = e.data().dyn_into::<Blob>() {
                    let file_reader = FileReader::new().unwrap();
                    let file_reader_clone = file_reader.clone();
                    let onloadend_cb = {
                        Closure::<dyn FnMut(_)>::new(move |_e: web_sys::ProgressEvent| {
                            console_log_jsvalue!(e);
                            let array =
                                js_sys::Uint8Array::new(&&file_reader_clone.result().unwrap());
                            sender_copy
                                .unbounded_send(array.to_vec())
                                .expect("Failed to write message to channel");
                            if let Some(waker_ref) = waker_double_clone.borrow_mut().as_ref() {
                                waker_ref.wake_by_ref();
                            }
                        })
                    };
                    file_reader.set_onloadend(Some(onloadend_cb.as_ref().unchecked_ref()));
                    file_reader
                        .read_as_array_buffer(&blob)
                        .expect("blob not readable");
                    onloadend_cb.forget();

                    console_log!("msg is blob");
                } else {
                    panic!("not recognized data type");
                }
            }) as Box<dyn FnMut(_)>)
        };

        ws_ref
            .as_ref()
            .borrow_mut()
            .set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
        onmessage_callback.forget();

        let onerr_callback = {
            Closure::wrap(Box::new(move |e: MessageEvent| {
                console_log_jsvalue!(e);
            }) as Box<dyn FnMut(_)>)
        };

        ws_ref
            .as_ref()
            .borrow_mut()
            .set_onerror(Some(onerr_callback.as_ref().unchecked_ref()));
        onerr_callback.forget();

        let write_waker = Rc::new(RefCell::new(None::<Waker>));
        let onconnect_callback = {
            let write_waker_clone = write_waker.clone();
            let read_waker_clone = read_waker.clone();
            Closure::wrap(Box::new(move |_e: MessageEvent| {
                console_log!("websocket connected");
                if let Some(write_ref) = write_waker_clone.borrow_mut().as_ref() {
                    write_ref.wake_by_ref();
                }

                if let Some(read_waker) = read_waker_clone.borrow_mut().as_ref() {
                    read_waker.wake_by_ref();
                }
            }) as Box<dyn FnMut(_)>)
        };

        ws_ref
            .as_ref()
            .borrow_mut()
            .set_onopen(Some(onconnect_callback.as_ref().unchecked_ref()));
        onconnect_callback.forget();

        let onclose_callback = {
            let write_waker_clone = write_waker.clone();
            let read_waker_clone = read_waker.clone();
            Closure::wrap(Box::new(move |_e: MessageEvent| {
                console_log!("websocket closed");
                if let Some(write_ref) = write_waker_clone.borrow_mut().as_ref() {
                    write_ref.wake_by_ref();
                }

                if let Some(read_waker) = read_waker_clone.borrow_mut().as_ref() {
                    read_waker.wake_by_ref();
                }
            }) as Box<dyn FnMut(_)>)
        };

        ws_ref
            .as_ref()
            .borrow_mut()
            .set_onclose(Some(onclose_callback.as_ref().unchecked_ref()));
        onclose_callback.forget();

        return Ok(WebSocketStream {
            ws: ws_ref.clone(),
            read_receiver: reader,
            read_waker: read_waker,
            write_waker: write_waker,
            temp_read_buffer: Vec::new(),
        });
    }
}

#[cfg(target_family = "wasm")]
unsafe impl Send for WebSocketStream {}

#[cfg(target_family = "wasm")]
impl Unpin for WebSocketStream {}
