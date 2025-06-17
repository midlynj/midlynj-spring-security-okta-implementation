package com.example.books.interfaces;

import com.example.books.model.Book;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;

public interface BookInterface {
    ResponseEntity<Book> getBookById(@PathVariable String bookId);
}
