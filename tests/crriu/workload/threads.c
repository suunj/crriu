#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  c = PTHREAD_COND_INITIALIZER;
static int turn = 0, count = 0;
static void* worker(void* arg) {
    int me = (int)(long)arg;
    while (1) {
        pthread_mutex_lock(&m);
        while (turn != me && count < 40) pthread_cond_wait(&c, &m);
        if (count >= 40) { pthread_cond_signal(&c); pthread_mutex_unlock(&m); return 0; }
        printf("thread %d: %d\n", me, count++); fflush(stdout);
        turn = 1 - me; pthread_cond_signal(&c);
        pthread_mutex_unlock(&m);
        usleep(200000);
    }
}
int main(void) {
    pthread_t t1, t2;
    pthread_create(&t1, 0, worker, (void*)0);
    pthread_create(&t2, 0, worker, (void*)1);
    pthread_join(t1, 0); pthread_join(t2, 0);
    return 0;
}
