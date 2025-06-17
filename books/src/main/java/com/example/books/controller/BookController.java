package com.example.books.controller;

import com.example.books.model.Book;
import com.example.books.service.BookServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/book")
public class BookController {
    @Autowired
    BookServiceImpl bookService;
    @GetMapping(path = "")
    public String helloWorld() {
        return "HELLO WORLD";
    }

    @GetMapping(path = "/admin")
    public String adminPortal() {
        return "Hello this is the Admin Portal";
    }
    @GetMapping(path = "/{bookId}")
    public ResponseEntity<Book> getBookById(@PathVariable String bookId) {
        return bookService.getBookById(bookId);
    }

}
