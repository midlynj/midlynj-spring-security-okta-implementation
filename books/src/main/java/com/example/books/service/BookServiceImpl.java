package com.example.books.service;

import com.example.books.model.Book;
import com.example.books.interfaces.BookInterface;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.Refill;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;

import java.time.Duration;
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

    @Override
    public String healthCheck() {
        Bucket bucket = Bucket.builder()
                .addLimit(Bandwidth.classic(10, Refill.intervally(10, Duration.ofMinutes(1))))
                .addLimit(Bandwidth.classic(5,Refill.intervally(5, Duration.ofSeconds(20))))
                .build();

        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        if (probe.isConsumed()) {
            System.out.printf("Token remaining: %s. %n", probe.getRemainingTokens());
            return "Books Api up and running";
        }

        System.out.printf("Seconds before retry: %s. %n ",probe.getNanosToWaitForRefill()/1_000_000_000);
        return "Too many calls in short time please wait";
    }
}
