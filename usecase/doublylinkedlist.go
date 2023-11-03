package usecase

type doublyLinkedList[T any] struct {
	head *item[T]
	tail *item[T]
}

type item[T any] struct {
	prev  *item[T]
	next  *item[T]
	value T
}

func (l *doublyLinkedList[T]) empty() bool {
	return l.head == nil
}

func (l *doublyLinkedList[T]) append(v T) *item[T] {
	newItem := &item[T]{
		value: v,
		prev:  l.tail,
	}
	if l.head == nil {
		// empty list, item becomes first and last item
		l.head = newItem
	} else {
		// non-empty list, item becomes last item
		l.tail.next = newItem
	}
	l.tail = newItem
	return newItem
}

func (l *doublyLinkedList[T]) remove(this *item[T]) {
	if this.prev == nil {
		// no prev, this is head, next becomes head
		l.head = this.next
	} else {
		// there's items after this
		this.prev.next = this.next
	}
	if this.next == nil {
		// this is tail, so prev becomes tail
		l.tail = this.prev
	} else {
		// this isn't tail (more items after this), so prev becomes tail
		this.next.prev = this.prev
	}
}
