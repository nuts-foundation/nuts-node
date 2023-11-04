/*
 * Copyright (C) 2023 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

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
