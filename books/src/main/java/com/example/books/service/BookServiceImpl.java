package com.example.books.service;

import com.example.books.model.Book;
import com.example.books.interfaces.BookInterface;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.UUID;

@Service
@AllArgsConstructor
public class BookServiceImpl implements BookInterface {
    @Override
    public ResponseEntity<Book> getBookById(@PathVariable String bookId) {
        Book book = new Book(bookId, UUID.randomUUID().toString(), "API Security",
                "SKB Publishers", "01-02-2010");

        return ResponseEntity.ok(book);
    }
}
